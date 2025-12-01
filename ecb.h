#ifndef ECB_H
#define ECB_H

#include <stdint.h>

void pad(uint8_t *text, int *text_len, int block_size);
int  unpad(uint8_t *text, int *text_len, int block_size);

// AES-128 ECB + PKCS7
int encrypt_ecb(const uint8_t *key,
                uint8_t *plaintext, int plaintext_len,
                uint8_t *ciphertext, int block_size,
                int *ciphertext_len);

int decrypt_ecb(const uint8_t *key,
                const uint8_t *ciphertext, int ciphertext_len,
                uint8_t *plaintext, int block_size,
                int *plaintext_len);

#endif
