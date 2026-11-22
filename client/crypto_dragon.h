#pragma once

#include <stdint.h>
#include <sodium.h>
#include <winsock2.h>
#include <stdatomic.h>

#include "transport.h"

typedef _Atomic uint64_t dr_ctr_t;

static inline uint64_t dr_ctr_next(dr_ctr_t* ctr) {
    return atomic_fetch_add(ctr, 1);
}

#define KEY_LEN        32
#define NONCE_LEN      12
#define TAG_LEN        16
#define PLAINTEXT_SIZE 2048
#define FRAME_SIZE     (PLAINTEXT_SIZE + TAG_LEN) 
#define CTR_HDR        8
#define WIRE_FRAME_SIZE (CTR_HDR + FRAME_SIZE)     
#define REKEY_INTERVAL  1000

int send_all(transport_conn_t *conn, transport_t *tran,
             const void *data, size_t len);
int recv_all(transport_conn_t *conn, transport_t *tran,
             void *buf, size_t len);

int dragon_handshake_client(transport_conn_t *conn, transport_t *tran,
                            const uint8_t server_pub[32],
                            uint8_t key_enc[KEY_LEN],
                            uint8_t base_iv[NONCE_LEN],
                            uint8_t chain_key[KEY_LEN]);

int dragon_handshake_with_father(transport_conn_t *conn, transport_t *tran,
                                 uint8_t key_enc[KEY_LEN],
                                 uint8_t base_iv[NONCE_LEN]);

int dragon_handshake_http_child(transport_conn_t *conn, transport_t *trans,
                                uint8_t key_enc[KEY_LEN],
                                uint8_t base_iv[NONCE_LEN]);

void dragon_derive_keys(const uint8_t key_enc[KEY_LEN],
                        const uint8_t base_iv[NONCE_LEN],
                        const uint8_t chain_key[KEY_LEN],
                        int is_server,
                        uint8_t key_tx[KEY_LEN],
                        uint8_t iv_tx[NONCE_LEN],
                        uint8_t ck_tx[KEY_LEN],
                        uint8_t key_rx[KEY_LEN],
                        uint8_t iv_rx[NONCE_LEN],
                        uint8_t ck_rx[KEY_LEN]);

void dragon_rekey(uint8_t key[KEY_LEN], uint8_t ck[KEY_LEN]);

int dragon_encrypt_frame(const uint8_t key[KEY_LEN],
                         const uint8_t base_iv[NONCE_LEN],
                         dr_ctr_t *ctr64,
                         const uint8_t plain[PLAINTEXT_SIZE],
                         uint8_t wire[WIRE_FRAME_SIZE]);

int dragon_decrypt_frame(const uint8_t key[KEY_LEN],
                         const uint8_t base_iv[NONCE_LEN],
                         const uint8_t wire[WIRE_FRAME_SIZE],
                         uint8_t plain[PLAINTEXT_SIZE],
                         uint64_t *ctr_out);

int dragon_encryption_blob(const uint8_t key[KEY_LEN],
                           const uint8_t base_iv[NONCE_LEN],
                           dr_ctr_t *ctr,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t *output,
                           uint16_t *output_len);

int dragon_decrypt_blob(const uint8_t key[KEY_LEN],
                        const uint8_t base_iv[NONCE_LEN],
                        const uint8_t *input,
                        size_t input_len,
                        uint8_t *output,
                        uint16_t *output_len);