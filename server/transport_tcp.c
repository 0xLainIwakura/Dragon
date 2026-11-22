/*==========================================================================
 * transport_tcp.c  -  TCP transport backend (server Linux)
 *==========================================================================*/
 
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "transport.h"
#include "padding.h"
#include "crypto_dragon.h"

struct transport_conn {
    int fd;
    struct sockaddr_in addr;
};

static uint16_t g_tcp_pad_min = 0;
static uint16_t g_tcp_pad_max = 0;

void tcp_set_padding(uint16_t pad_min, uint16_t pad_max)
{
    g_tcp_pad_min = pad_min;
    g_tcp_pad_max = pad_max;
}
 
/* =========================================================================
 * transport_t callbacks
 * ====================================================================== */
 
static int tcp_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("[TCP] socket"); return -1; }
 
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
 
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port        = htons((uint16_t)port);
 
    if (bind(fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("[TCP] bind"); close(fd); return -1;
    }
    if (listen(fd, 16) < 0) {
        perror("[TCP] listen"); close(fd); return -1;
    }
    return fd;
}
 
static transport_conn_t *tcp_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("[TCP] socket"); return NULL; }
 
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "[TCP] invalid address: %s\n", host);
        close(fd);
        return NULL;
    }
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("[TCP] connect");
        close(fd);
        return NULL;
    }
 
    transport_conn_t *conn = malloc(sizeof *conn);
    if (!conn) { close(fd); return NULL; }
    conn->fd   = fd;
    conn->addr = sa;
    return conn;
}
 
static transport_conn_t *tcp_accept(int listener_fd,
                                     struct sockaddr_in *out_addr)
{
    struct sockaddr_in caddr;
    socklen_t clen = sizeof caddr;
 
    int cfd = accept(listener_fd, (struct sockaddr*)&caddr, &clen);
    if (cfd < 0) return NULL;
 
    if (out_addr) *out_addr = caddr;
 
    transport_conn_t *conn = malloc(sizeof *conn);
    if (!conn) { close(cfd); return NULL; }
    conn->fd   = cfd;
    conn->addr = caddr;
    return conn;
}

static int tcp_send_raw(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(fd, (const char*)buf + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        sent += r;
    }
    return (int)sent;
}

static int tcp_recv_raw(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(fd, (char*)buf + got, len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return (int)got;
}
 
static int tcp_send(transport_conn_t *conn, const uint8_t *buf, size_t len)
{
    uint8_t pad[1024];
    int pad_len = 0;

    if (len == WIRE_FRAME_SIZE && g_tcp_pad_max > 0)
        pad_len = generate_padding(g_tcp_pad_min, g_tcp_pad_max, pad, 1024);

    uint32_t total = htonl((uint32_t)(len + pad_len));

    if (tcp_send_raw(conn->fd, &total, 4) < 0) return -1;
    if (tcp_send_raw(conn->fd, buf, len) < 0) return -1;
    if (pad_len > 0)
        if (tcp_send_raw(conn->fd, pad, pad_len) < 0) return -1;

    return (int)len;
}
 
static int tcp_recv(transport_conn_t *conn, uint8_t *buf, size_t len)
{
    uint32_t net_total;
    if (tcp_recv_raw(conn->fd, &net_total, 4) < 0) return -1;
    uint32_t total = ntohl(net_total);

    if (total < (uint32_t)len) return -1;

    if (tcp_recv_raw(conn->fd, buf, len) < 0) return -1;

    uint32_t remaining = total - (uint32_t)len;
    while (remaining > 0) {
        char discard[512];
        uint32_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
        if (tcp_recv_raw(conn->fd, discard, chunk) < 0) return -1;
        remaining -= chunk;
    }

    return (int)len;
}
 
static int tcp_poll(transport_conn_t *conn, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(conn->fd, &rfds);
 
    if (timeout_ms < 0) {
        int r = select(conn->fd + 1, &rfds, NULL, NULL, NULL);
        if (r < 0) return -1;
        return FD_ISSET(conn->fd, &rfds) ? 1 : 0;
    }
 
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
 
    int r = select(conn->fd + 1, &rfds, NULL, NULL, &tv);
    if (r < 0)  return -1;
    if (r == 0) return 0;
    return FD_ISSET(conn->fd, &rfds) ? 1 : 0;
}
 
static void tcp_close(transport_conn_t *conn)
{
    if (!conn) return;
    shutdown(conn->fd, SHUT_RDWR);
    close(conn->fd);
    free(conn);
}
 
static void tcp_close_listener(int fd)
{
    shutdown(fd, SHUT_RDWR);
    close(fd);
}
 
static int tcp_get_fd(transport_conn_t *conn)
{
    return conn ? conn->fd : -1;
}
 
transport_t TRANSPORT_TCP = {
    .name           = "tcp",
    .listen         = tcp_listen,
    .connect        = tcp_connect,
    .accept         = tcp_accept,
    .send           = tcp_send,
    .recv           = tcp_recv,
    .poll           = tcp_poll,
    .close          = tcp_close,
    .close_listener = tcp_close_listener,
    .get_fd         = tcp_get_fd,
};