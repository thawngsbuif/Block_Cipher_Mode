#ifndef AES_H
#define AES_H

#include <stdint.h>

// AES-128: key 16 byte, block 16 byte
void aes_encrypt_block(const uint8_t *key,
                       const uint8_t *in,
                       uint8_t *out);

void aes_decrypt_block(const uint8_t *key,
                       const uint8_t *in,
                       uint8_t *out);

#endif // AES_H
