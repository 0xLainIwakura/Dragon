#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "transport.h"

#pragma comment(lib, "Ws2_32.lib")


/* ========================================
   TCP CONNECTION
   ======================================== */ 

struct transport_conn {
    SOCKET sock;
};


/* ========================================
   SEND
   ======================================== */

static int tcp_send(
        transport_conn_t *conn,
        const uint8_t *buf,
        size_t len)
{
    size_t sent = 0;

    while (sent < len)
    {
        int r = send(conn->sock,
                     (char*)buf + sent,
                     len - sent,
                     0);

        if (r <= 0)
            return -1;

        sent += r;
    }

    return sent;
}


/* ========================================
   RECV
   ======================================== */

static int tcp_recv(
        transport_conn_t *conn,
        uint8_t *buf,
        size_t len)
{
    size_t received = 0;

    while (received < len)
    {
        int r = recv(conn->sock,
                     (char*)buf + received,
                     len - received,
                     0);

        if (r <= 0)
            return -1;

        received += r;
    }

    return received;
}


/* ========================================
   POLL (select wrapper)
   ======================================== */

static int tcp_poll(transport_conn_t *conn, int timeout_ms)
{
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(conn->sock, &rfds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    /* Windows ignora il primo parametro */
    return select(0, &rfds, NULL, NULL, &tv);
}


/* ========================================
   CLOSE
   ======================================== */

static void tcp_close(transport_conn_t *conn)
{
    if (!conn)
        return;

    closesocket(conn->sock);
    free(conn);
}

static transport_conn_t *
tcp_connect(const char *host, int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == INVALID_SOCKET)
        return NULL;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return NULL;
    }

    transport_conn_t *conn = malloc(sizeof(*conn));
    conn->sock = s;

    return conn;
}

static transport_conn_t *
tcp_accept(int listener_fd, struct sockaddr_in *addr)
{
    int len = sizeof(*addr);

    SOCKET s = accept((SOCKET)listener_fd,
                      (struct sockaddr*)addr,
                      &len);

    if (s == INVALID_SOCKET)
        return NULL;

    transport_conn_t *conn = malloc(sizeof(*conn));
    conn->sock = s;

    return conn;
}

static int tcp_for_listen(int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == INVALID_SOCKET)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(s);
        return -1;
    }

    return (int)s;
}


static void tcp_close_listener(int listener_fd)
{
    closesocket((SOCKET)listener_fd);
}



int transport_tcp_get_fd(transport_conn_t *conn)
{
    return (int)conn->sock;
}

/* ========================================
   EXPORT TRANSPORT
   ======================================== */

transport_t TRANSPORT_TCP = {
    .name = "tcp",

    .listen = tcp_for_listen,
    .connect = tcp_connect,
    .accept = tcp_accept,

    .send = tcp_send,
    .recv = tcp_recv,
    .poll = tcp_poll,

    .close = tcp_close,
    .close_listener = tcp_close_listener,

    .get_fd = transport_tcp_get_fd
};