#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define OPCODE_PROFILE "0x50"

#define MP_USER_AGENT_MAX    256
#define MP_CONTENT_TYPE_MAX  128
#define MP_PATH_MAX           64
#define MP_EXTRA_HEADERS_MAX 512
#define MP_PIPE_NAME_MAX     128
#define MP_DNS_DOMAIN_MAX    256

typedef struct __attribute__((packed)) {
    /* -- common (all transports) -- */
    uint16_t  beacon_interval_s;   /* seconds between beacons           */
    uint8_t   jitter_pct;          /* 0-50, randomness percentage       */
    uint16_t  reconnect_delay_ms;  /* ms before reconnect attempt       */

    /* -- HTTP / HTTPS -- */
    char      http_user_agent[MP_USER_AGENT_MAX];
    char      http_content_type[MP_CONTENT_TYPE_MAX];
    char      http_path_data[MP_PATH_MAX];
    char      http_path_hs[MP_PATH_MAX];
    char      http_extra_headers[MP_EXTRA_HEADERS_MAX];

    /* -- SMB -- */
    char      smb_pipe_name[MP_PIPE_NAME_MAX];

    /* -- DNS -- */
    char      dns_domain[MP_DNS_DOMAIN_MAX];
    uint16_t  dns_poll_ms;

    /* -- random packet size -- */
    uint16_t pkt_pad_min;
    uint16_t pkt_pad_max;

} malleable_profile_t;

_Static_assert(sizeof(malleable_profile_t) <= 1998, "malleable_profile_t exceeds PACKET_DRAGON payload");

static inline int profile_serialize(const malleable_profile_t *p, uint8_t *buf, uint16_t *out_len)
{
    if (!p || !buf || !out_len) return -1;
    memcpy(buf, p, sizeof(malleable_profile_t));
    *out_len = (uint16_t)sizeof(malleable_profile_t);
    return 0;
}

static inline int profile_deserialize(const uint8_t *buf, uint16_t len, malleable_profile_t *p)
{
    if (!buf || !p) return -1;
    if (len < sizeof(malleable_profile_t)) return -1;
    memcpy(p, buf, sizeof(malleable_profile_t));
    return 0;
}

static inline void profile_dump(const malleable_profile_t *p)
{
    if (!p) return;
    printf("[PROFILE] beacon=%us jitter=%u%% reconnect=%ums\n", p->beacon_interval_s, p->jitter_pct, p->reconnect_delay_ms);
    if (p->http_user_agent[0])
        printf("[PROFILE] http: ua=\"%.40s...\" path_data=\"%s\" path_hs=\"%s\"\n", p->http_user_agent, p->http_path_data, p->http_path_hs);
    if (p->smb_pipe_name[0])
        printf("[PROFILE] smb: pipe=\"%s\"\n", p->smb_pipe_name);
    if (p->dns_domain[0])
        printf("[PROFILE] dns: domain=\"%s\" poll=%ums\n", p->dns_domain, p->dns_poll_ms);
}