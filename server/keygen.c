#include <sodium.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int compute_cert_pin(const char *cert_path, uint8_t pin[32]) {
    FILE *f = fopen(cert_path, "r");
    if (!f) return -1;

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert) return -1;

    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    X509_free(cert);
    if (der_len <= 0) return -1;

    unsigned int hash_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, der, der_len);
    EVP_DigestFinal_ex(ctx, pin, &hash_len);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(der);

    return (hash_len == 32) ? 0 : -1;
}

static void write_byte_array(FILE *f, const char *name,
                              const uint8_t *data, int len) {
    fprintf(f, "static const uint8_t %s[%d] = {\n ", name, len);
    for (int i = 0; i < len; i++) {
        fprintf(f, " 0x%02x", data[i]);
        if (i < len - 1) fprintf(f, ",");
        if ((i + 1) % 8 == 0 && i < len - 1) fprintf(f, "\n ");
    }
    fprintf(f, "\n};\n\n");
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    uint8_t pub[32], priv[32];
    crypto_box_keypair(pub, priv);

    /* server_priv.bin */
    FILE *f = fopen("server_priv.bin", "wb");
    if (!f) { perror("server_priv.bin"); return 1; }
    fwrite(priv, 1, 32, f);
    fclose(f);
    sodium_memzero(priv, 32);

    /* server_pub.h */
    f = fopen("server_pub.h", "w");
    if (!f) { perror("server_pub.h"); return 1; }

    fprintf(f, "#pragma once\n#include <stdint.h>\n\n");
    write_byte_array(f, "SERVER_PUB", pub, 32);

    uint8_t cert_pin[32] = {0};
    if (compute_cert_pin("server.crt", cert_pin) == 0) {
        write_byte_array(f, "SERVER_CERT_PIN", cert_pin, 32);
    } else {
        /* No cert - write zeroed pin so code compiles.
         * HTTPS pinning will be disabled. Regenerate after
         * creating server.crt to enable it. */
        write_byte_array(f, "SERVER_CERT_PIN", cert_pin, 32);
    }

    fclose(f);

    printf("Generated:\n");
    printf("  server_priv.bin   (server loads at runtime)\n");
    printf("  server_pub.h      (copy to client/ or use generate)\n");
    if (compute_cert_pin("server.crt", cert_pin) == 0)
        printf("  SERVER_CERT_PIN   (computed from server.crt)\n");
    else
        printf("  SERVER_CERT_PIN   (zeroed - no server.crt found, run keygen again after creating it)\n");

    return 0;
}

