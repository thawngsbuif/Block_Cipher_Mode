#include "ecb.h"
#include "aes.h"
#include <string.h>

void pad(uint8_t *text, int *text_len, int block_size) {
    int pad_len = block_size - (*text_len % block_size);
    for (int i = 0; i < pad_len; i++) text[*text_len + i] = (uint8_t)pad_len;
    *text_len += pad_len;
}

int unpad(uint8_t *text, int *text_len, int block_size) {
    if (*text_len <= 0 || (*text_len % block_size) != 0) return 0;

    int pad_len = text[*text_len - 1];
    if (pad_len <= 0 || pad_len > block_size) return 0;

    for (int i = 0; i < pad_len; i++)
        if (text[*text_len - 1 - i] != (uint8_t)pad_len) return 0;

    *text_len -= pad_len;
    return 1;
}

int encrypt_ecb(const uint8_t *key,
                uint8_t *plaintext, int plaintext_len,
                uint8_t *ciphertext, int block_size,
                int *ciphertext_len) {
    if (block_size != 16) return 0; // AES block = 16

    int padded_len = plaintext_len;
    pad(plaintext, &padded_len, block_size);

    // FIX: số block tính theo padded_len
    for (int i = 0; i < padded_len; i += block_size) {
        aes_encrypt_block(key, plaintext + i, ciphertext + i);
    }

    *ciphertext_len = padded_len;
    return 1;
}

int decrypt_ecb(const uint8_t *key,
                const uint8_t *ciphertext, int ciphertext_len,
                uint8_t *plaintext, int block_size,
                int *plaintext_len) {
    if (block_size != 16) return 0;
    if (ciphertext_len <= 0 || (ciphertext_len % block_size) != 0) return 0;

    for (int i = 0; i < ciphertext_len; i += block_size) {
        aes_decrypt_block(key, ciphertext + i, plaintext + i);
    }

    int len = ciphertext_len;
    if (!unpad(plaintext, &len, block_size)) return 0;

    *plaintext_len = len;
    return 1;
}
