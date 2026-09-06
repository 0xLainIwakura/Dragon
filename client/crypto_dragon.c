#include "crypto_dragon.h"
#include <string.h>

int send_all(transport_conn_t *conn, transport_t *trans, const void *data, size_t len) {
    const char *buf = (const char *)data;
    size_t total_sent = 0;

    while (total_sent < len) {
        int sent = trans->send(conn, buf + total_sent, (int)(len - total_sent));
        if (sent<=0) {
            return 0; 
        }
        total_sent += sent;
    }
    return 1; 
}

int recv_all(transport_conn_t *conn, transport_t *trans, void *buf, size_t len) {
    uint8_t *p   = (uint8_t *)buf;
    size_t   got = 0;

    while (got < len) {
        int r = trans->recv(conn, (char*)p + got, (int)(len - got));
        if (r <= 0) return 0;          
        got += (size_t)r;
    }
    return 1;
}

static void derive_nonce(uint8_t n[NONCE_LEN], const uint8_t iv[NONCE_LEN], uint64_t ctr) {
    memcpy(n, iv, NONCE_LEN);
    for (int i = 0; i < 8; ++i) {
        n[i] ^= (uint8_t)(ctr >> (8 * i));
    }
}

/*====================== HANDSHAKE - CLIENT ==========================*/
int dragon_handshake_client(transport_conn_t *conn, transport_t *trans, const uint8_t server_pub[32], uint8_t key_enc[KEY_LEN], uint8_t base_iv[NONCE_LEN], uint8_t chain_key[KEY_LEN]) {
    uint8_t cli_pub[32], cli_priv[32];
    crypto_box_keypair(cli_pub, cli_priv);        /* key ephem */

   printf("[HS] sending cli_pub 32 byte...\n");
    if (!send_all(conn, trans, cli_pub, 32)) {
        return -1;
    }
    printf("[HS] send_all OK\n");

    /* secret shared with X25519 ------------------------------------ */
    uint8_t ss[32];
    if (crypto_scalarmult(ss, cli_priv, server_pub) != 0)
        return -1;

    /* HKDF -> key_enc | base_iv | chain_key ---------------------------- */
    uint8_t km[64];
    crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", ss);

    crypto_generichash(key_enc,   KEY_LEN,   km, 64, (uint8_t*)"enc", 3);
    crypto_generichash(base_iv,   NONCE_LEN, km, 64, (uint8_t*)"iv",  2);
    crypto_generichash(chain_key, KEY_LEN,   km, 64, (uint8_t*)"ck",  2);

    sodium_memzero(cli_priv, sizeof cli_priv);
    sodium_memzero(ss, sizeof ss);
    sodium_memzero(km, sizeof km);
    return 0;
}

int dragon_handshake_with_father(transport_conn_t *conn, transport_t *trans, uint8_t key_enc[KEY_LEN], uint8_t base_iv[NONCE_LEN]) {
    uint8_t pub_father[32];
    uint8_t pub_client[32], priv_client[32];
    uint8_t shared[32];

    // 1. Receive public key from father
    if (!recv_all(conn, trans, pub_father, 32)) {
        return -1;
    }

    // 2. Generate the ephimeral keypair of sub-client
    crypto_box_keypair(pub_client, priv_client);

    // 3. Send pubkey of sub-client to the father
    if (!send_all(conn, trans, pub_client, 32)) {
        return -1;
    }

    // 4. Derive key
    if (crypto_scalarmult(shared, priv_client, pub_father) != 0) {
        return -1;
    }

    // 5. Derive key_enc and base_iv from shared secret
    uint8_t km[64];
    crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", shared);
    crypto_generichash(key_enc,   KEY_LEN,   km, 64, (uint8_t*)"enc", 3);
    crypto_generichash(base_iv,   NONCE_LEN, km, 64, (uint8_t*)"iv",  2);

    sodium_memzero(priv_client, sizeof priv_client);
    sodium_memzero(shared, sizeof shared);
    sodium_memzero(km, sizeof km);
    return 0;
}

int dragon_encrypt_frame(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr64, const uint8_t plain[PLAINTEXT_SIZE], uint8_t frame[FRAME_SIZE]) {
    printf("[debug] Encrypt with ctr=%llu\n", *ctr64);
    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr64);
    derive_nonce(nonce, base_iv, cur);
    return crypto_aead_chacha20poly1305_ietf_encrypt(frame, NULL, plain, PLAINTEXT_SIZE, NULL, 0, NULL, nonce, key);
}

int dragon_decrypt_frame(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr64, const uint8_t frame[FRAME_SIZE], uint8_t plain[PLAINTEXT_SIZE]) {
    printf("[debug] Decrypting with ctr=%llu\n", *ctr64);
    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr64);
    derive_nonce(nonce, base_iv, cur);
    return crypto_aead_chacha20poly1305_ietf_decrypt(plain, NULL, NULL, frame, FRAME_SIZE, NULL, 0, nonce, key);
}

int dragon_decrypt_payload(const uint8_t key[KEY_LEN], const uint8_t base_iv[NONCE_LEN], dr_ctr_t *ctr, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext) {
    if (ciphertext_len < TAG_LEN) return -1;
    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr);
    derive_nonce(nonce, base_iv, cur);
    
    return crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, NULL, NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce, key
    );
}

/* ============================================================= */
/*  Chiper a variable-lenght blob        (≤ 1998-TAG_LEN byte)    */
/*  key/base_iv/ctr  : key and counter                            */
/*  input / input_len: plaintext                                  */
/*  output           : ciphertext+tag                             */
/*  output_len       : written lenght                             */
/* ============================================================= */
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

    if (*ctr == UINT64_MAX)             /* overflow nonce                */
        return -2;

    uint8_t nonce[NONCE_LEN];
    uint64_t cur = dr_ctr_next(ctr);
    derive_nonce(nonce, base_iv, cur);

    unsigned long long clen = 0;

    /* libsodium accepted m == NULL when mlen == 0 */
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            output, &clen,
            input_len ? input : NULL,          
            (unsigned long long)input_len,
            NULL, 0,
            NULL,
            nonce, key) != 0)
        return -3;

    *output_len = (uint16_t)clen;              /* = TAG_LEN if input_len==0 */
    return 0;
}

int dragon_handshake_http_child( transport_conn_t *conn, transport_t *trans, uint8_t key_enc[KEY_LEN], uint8_t base_iv[NONCE_LEN]) {
    uint8_t pub_client[32], priv_client[32];
    uint8_t pub_father[32];
    uint8_t shared[32];

    /* generate chiave ephemeral */
    crypto_box_keypair(pub_client, priv_client);

    printf("[HS-HTTP-CHILD] sending pub_client\n"); fflush(stdout);

    /* send pub_client */
    if (!send_all(conn, trans, pub_client, 32))
        return -1;


    printf("[HS-HTTP-CHILD] waiting pub_father\n"); fflush(stdout);
    /* recieve pub_father */
    if (!recv_all(conn, trans, pub_father, 32))
        return -1;

    printf("[HS-HTTP-CHILD] pub_father received\n"); fflush(stdout);

    /* shared secret */
    if (crypto_scalarmult(shared, priv_client, pub_father) != 0)
        return -1;

    uint8_t km[64];

    crypto_kdf_derive_from_key(km, 64, 0x01, "DRAGONHS", shared);

    crypto_generichash(key_enc, KEY_LEN, km, 64, (uint8_t*)"enc", 3);
    crypto_generichash(base_iv, NONCE_LEN, km, 64, (uint8_t*)"iv", 2);

    sodium_memzero(priv_client, sizeof priv_client);
    sodium_memzero(shared, sizeof shared);
    sodium_memzero(km, sizeof km);

    return 0;
}