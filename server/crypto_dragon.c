#include "crypto_dragon.h"
#include <string.h>
#include <sys/socket.h>
#include "transport.h"

#define _GNU_SOURCE

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

static void derive_nonce(uint8_t n[NONCE_LEN], const uint8_t iv[NONCE_LEN], uint64_t ctr) {
    memcpy(n, iv, NONCE_LEN);
    // XOR iv and counter to create nonce
    for(int i = 0; i < 8; ++i) {
        n[i] ^= (uint8_t)(ctr >> (8*i));
    }
}

int dragon_handshake_server(transport_conn_t *conn, transport_t *trans, const uint8_t server_priv[32], uint8_t key_enc[KEY_LEN], uint8_t base_iv[NONCE_LEN], uint8_t chain_key[KEY_LEN]) {
    uint8_t cli_pub[32];
    size_t got = 0;

    while (got < 32) {
        int r = trans->recv(conn, cli_pub + got, 32 - got);
        if (r <= 0)
            return -1;
        got += r;
    }

    uint8_t ss[32];
    /* X25519 */
    if(crypto_scalarmult(ss, server_priv, cli_pub) != 0) {
        return -1;
    }     

    uint8_t km[64];
    crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", ss);      /* HKDF */
    crypto_generichash(key_enc, KEY_LEN, km, 64, (uint8_t *)"enc", 3);
    crypto_generichash(base_iv, NONCE_LEN, km, 64, (uint8_t *)"iv",  2);
    crypto_generichash(chain_key, KEY_LEN, km, 64, (uint8_t *)"ck",  2);

    return 0;
}

int dragon_encrypt_frame(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr64, const uint8_t plain[PLAINTEXT_SIZE], uint8_t frame[FRAME_SIZE]) {
    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr64);
    derive_nonce(nonce, base_iv, cur);
    return crypto_aead_chacha20poly1305_ietf_encrypt(frame, NULL, plain, PLAINTEXT_SIZE, NULL, 0, NULL, nonce, key);
}

int dragon_decrypt_frame(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr64, const uint8_t frame[FRAME_SIZE], uint8_t plain[PLAINTEXT_SIZE]) {
    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr64);
    derive_nonce(nonce, base_iv, cur);
    return crypto_aead_chacha20poly1305_ietf_decrypt(plain, NULL, NULL, frame, FRAME_SIZE, NULL, 0, nonce, key);
}

int dragon_encryption_blob(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr, const uint8_t *input, size_t input_len, uint8_t *output, uint16_t *output_len) {
    if (!key || !base_iv || !ctr || !output || !output_len)
        return -1;
    if (input_len > 0 && !input)
        return -1;

    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr);
    derive_nonce(nonce, base_iv, cur);

    unsigned long long clen = 0;


    
    if (crypto_aead_chacha20poly1305_ietf_encrypt(output, &clen,
            input, input_len,
            NULL, 0,   // no additional data
            NULL, nonce, key) != 0) {
        return -1; // encryption failed
    }

    *output_len = (uint16_t)clen;
    return 0;
}

int dragon_decrypt_blob(const uint8_t key[KEY_LEN],
        const uint8_t base_iv[NONCE_LEN],
        dr_ctr_t *ctr,
        const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        uint16_t *output_len)
    {
    if (!key || !base_iv || !ctr || !input || !output)
    return -1;
    if (input_len < crypto_aead_chacha20poly1305_ietf_ABYTES)
    return -2;

    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr);
    derive_nonce(nonce, base_iv, cur);

    unsigned long long pt_len = 0;

    

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
    output, &pt_len,
    NULL,
    input, input_len,
    NULL, 0,
    nonce, key) != 0)
    return -3;                              /* MAC mismatch */

    if (output_len) *output_len = (uint16_t)pt_len;
    return 0;
}