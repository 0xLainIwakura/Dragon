#ifndef TRANSPORT_H
#define TRANSPORT_H
 
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

typedef struct transport_conn transport_conn_t;
 
typedef struct transport_t {
 
    const char *name;
 
    /* -- SERVER SIDE --------------------------------------------------- */
    int               (*listen)(int port);
    transport_conn_t *(*accept)(int listener_fd, struct sockaddr_in *addr);
 
    /* -- CLIENT SIDE --------------------------------------------------- */

    transport_conn_t *(*connect)(const char *host, int port);
 
    /* -- I/O ----------------------------------------------------------- */
    int  (*send)(transport_conn_t *conn, const uint8_t *buf, size_t len);
    int  (*recv)(transport_conn_t *conn, uint8_t *buf, size_t len);
 
    /* -- POLL ---------------------------------------------------------- */
    int  (*poll)(transport_conn_t *conn, int timeout_ms);
 
    /* -- CLOSE --------------------------------------------------------- */
    void (*close)(transport_conn_t *conn);
    void (*close_listener)(int listener_fd);
 
    /* -- UTILITY ------------------------------------------------------- */
    int  (*get_fd)(transport_conn_t *conn);
 
} transport_t;
 
 
/* -- Backends available ----------------------------------------------- */
extern transport_t TRANSPORT_TCP;
extern transport_t TRANSPORT_HTTP;
extern transport_t TRANSPORT_HTTPS;
extern transport_t TRANSPORT_DNS;

void dns_server_set_domain(const char *domain);

void http_server_set_paths(const char *data, const char *hs);
void https_server_set_paths(const char *data, const char *hs);

transport_t *transport_get(const char *name);
 
#endif