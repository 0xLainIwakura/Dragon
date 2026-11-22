#include "crypto_dragon.h"
#include <string.h>
#include <sys/socket.h>
#include "transport.h"

#define _GNU_SOURCE

int send_all(transport_conn_t *conn,
             transport_t *trans, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t sent = 0;

    while (sent < len) {
        int r = trans->send(conn, p + sent, len - sent);
        if (r <= 0)
            return 0;
        sent += (size_t)r;
    }

    return 1;
}

int recv_all(transport_conn_t *conn,
             transport_t *trans, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;

    while (got < len) {
        int r = trans->recv(conn, p + got, len - got);
        if (r <= 0)
            return 0;
        got += (size_t)r;
    }

    return 1;
}

static void derive_nonce(uint8_t n[NONCE_LEN],
                         const uint8_t iv[NONCE_LEN], uint64_t ctr)
{
    memcpy(n, iv, NONCE_LEN);
    for (int i = 0; i < 8; ++i)
        n[i] ^= (uint8_t)(ctr >> (8 * i));
}

void dragon_derive_keys(const uint8_t key_enc[KEY_LEN],
                        const uint8_t base_iv[NONCE_LEN],
                        const uint8_t chain_key[KEY_LEN],
                        int is_server,
                        uint8_t key_tx[KEY_LEN],
                        uint8_t iv_tx[NONCE_LEN],
                        uint8_t ck_tx[KEY_LEN],
                        uint8_t key_rx[KEY_LEN],
                        uint8_t iv_rx[NONCE_LEN],
                        uint8_t ck_rx[KEY_LEN])
{
    uint8_t key_cs[KEY_LEN], key_sc[KEY_LEN];
    uint8_t iv_cs[NONCE_LEN], iv_sc[NONCE_LEN];
    uint8_t ck_cs[KEY_LEN], ck_sc[KEY_LEN];

    crypto_generichash(key_cs, KEY_LEN,  key_enc,   KEY_LEN,   (const uint8_t*)"kcs", 3);
    crypto_generichash(key_sc, KEY_LEN,  key_enc,   KEY_LEN,   (const uint8_t*)"ksc", 3);
    crypto_generichash(iv_cs,  NONCE_LEN,base_iv,   NONCE_LEN, (const uint8_t*)"ics", 3);
    crypto_generichash(iv_sc,  NONCE_LEN,base_iv,   NONCE_LEN, (const uint8_t*)"isc", 3);
    crypto_generichash(ck_cs,  KEY_LEN,  chain_key, KEY_LEN,   (const uint8_t*)"ccs", 3);
    crypto_generichash(ck_sc,  KEY_LEN,  chain_key, KEY_LEN,   (const uint8_t*)"csc", 3);

    if (is_server) {
        memcpy(key_tx, key_sc, KEY_LEN);   memcpy(key_rx, key_cs, KEY_LEN);
        memcpy(iv_tx,  iv_sc,  NONCE_LEN); memcpy(iv_rx,  iv_cs,  NONCE_LEN);
        memcpy(ck_tx,  ck_sc,  KEY_LEN);   memcpy(ck_rx,  ck_cs,  KEY_LEN);
    } else {
        memcpy(key_tx, key_cs, KEY_LEN);   memcpy(key_rx, key_sc, KEY_LEN);
        memcpy(iv_tx,  iv_cs,  NONCE_LEN); memcpy(iv_rx,  iv_sc,  NONCE_LEN);
        memcpy(ck_tx,  ck_cs,  KEY_LEN);   memcpy(ck_rx,  ck_sc,  KEY_LEN);
    }

    sodium_memzero(key_cs, KEY_LEN);  sodium_memzero(key_sc, KEY_LEN);
    sodium_memzero(iv_cs,  NONCE_LEN);sodium_memzero(iv_sc,  NONCE_LEN);
    sodium_memzero(ck_cs,  KEY_LEN);  sodium_memzero(ck_sc,  KEY_LEN);
}

void dragon_rekey(uint8_t key[KEY_LEN], uint8_t ck[KEY_LEN])
{
    uint8_t new_ck[KEY_LEN];
    crypto_generichash(new_ck, KEY_LEN, ck,     KEY_LEN, (const uint8_t*)"nxt", 3);
    crypto_generichash(key,    KEY_LEN, new_ck, KEY_LEN, (const uint8_t*)"enc", 3);
    sodium_memzero(ck, KEY_LEN);
    memcpy(ck, new_ck, KEY_LEN);
    sodium_memzero(new_ck, KEY_LEN);
}

int dragon_handshake_server(transport_conn_t *conn, transport_t *trans,
                             const uint8_t server_priv[32],
                             uint8_t key_enc[KEY_LEN],
                             uint8_t base_iv[NONCE_LEN],
                             uint8_t chain_key[KEY_LEN])
{
    uint8_t cli_pub[32];
    size_t got = 0;

    while (got < 32) {
        int r = trans->recv(conn, cli_pub + got, 32 - got);
        if (r <= 0)
            return -1;
        got += r;
    }

    uint8_t ss[32];
    if (crypto_scalarmult(ss, server_priv, cli_pub) != 0)
        return -1;

    uint8_t km[64];
    crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", ss);
    crypto_generichash(key_enc,   KEY_LEN,   km, 64, (uint8_t *)"enc", 3);
    crypto_generichash(base_iv,   NONCE_LEN, km, 64, (uint8_t *)"iv",  2);
    crypto_generichash(chain_key, KEY_LEN,   km, 64, (uint8_t *)"ck",  2);

    sodium_memzero(ss, sizeof ss);
    sodium_memzero(km, sizeof km);

    return 0;
}

int dragon_encrypt_frame(const uint8_t key[KEY_LEN],
                         const uint8_t base_iv[NONCE_LEN],
                         dr_ctr_t *ctr64,
                         const uint8_t plain[PLAINTEXT_SIZE],
                         uint8_t wire[WIRE_FRAME_SIZE])
{
    uint64_t cur = dr_ctr_next(ctr64);

    memcpy(wire, &cur, CTR_HDR);

    uint8_t nonce[NONCE_LEN];
    derive_nonce(nonce, base_iv, cur);

    return crypto_aead_chacha20poly1305_ietf_encrypt(
            wire + CTR_HDR, NULL,
            plain, PLAINTEXT_SIZE,
            NULL, 0, NULL, nonce, key);
}

int dragon_decrypt_frame(const uint8_t key[KEY_LEN],
                         const uint8_t base_iv[NONCE_LEN],
                         const uint8_t wire[WIRE_FRAME_SIZE],
                         uint8_t plain[PLAINTEXT_SIZE],
                         uint64_t *ctr_out)
{
    uint64_t ctr;
    memcpy(&ctr, wire, CTR_HDR);
    if (ctr_out) *ctr_out = ctr;

    uint8_t nonce[NONCE_LEN];
    derive_nonce(nonce, base_iv, ctr);

    return crypto_aead_chacha20poly1305_ietf_decrypt(
            plain, NULL, NULL,
            wire + CTR_HDR, FRAME_SIZE,
            NULL, 0, nonce, key);
}

int dragon_encryption_blob(const uint8_t key[KEY_LEN],
                            const uint8_t base_iv[NONCE_LEN],
                            dr_ctr_t *ctr,
                            const uint8_t *input,
                            size_t input_len,
                            uint8_t *output,
                            uint16_t *output_len)
{
    if (!key || !base_iv || !ctr || !output || !output_len)
        return -1;
    if (input_len > 0 && !input)
        return -1;
    if (*ctr == UINT64_MAX)
        return -2;

    uint64_t cur = dr_ctr_next(ctr);

    memcpy(output, &cur, CTR_HDR);

    uint8_t nonce[NONCE_LEN];
    derive_nonce(nonce, base_iv, cur);

    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            output + CTR_HDR, &clen,
            input_len ? input : NULL,
            (unsigned long long)input_len,
            NULL, 0, NULL, nonce, key) != 0)
        return -3;

    *output_len = (uint16_t)(CTR_HDR + clen);   /* 8 + ciphertext + tag */
    return 0;
}

int dragon_decrypt_blob(const uint8_t key[KEY_LEN],
                        const uint8_t base_iv[NONCE_LEN],
                        const uint8_t *input,
                        size_t input_len,
                        uint8_t *output,
                        uint16_t *output_len)
{
    if (!key || !base_iv || !input || !output)
        return -1;
    if (input_len < CTR_HDR + crypto_aead_chacha20poly1305_ietf_ABYTES)
        return -2;

    uint64_t ctr;
    memcpy(&ctr, input, CTR_HDR);

    uint8_t nonce[NONCE_LEN];
    derive_nonce(nonce, base_iv, ctr);

    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &pt_len, NULL,
            input + CTR_HDR, input_len - CTR_HDR,
            NULL, 0, nonce, key) != 0)
        return -3;                              /* MAC mismatch */

    if (output_len) *output_len = (uint16_t)pt_len;
    return 0;
}