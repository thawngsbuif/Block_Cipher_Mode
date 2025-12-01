#include "cbc.h"
#include "aes.h"
#include <string.h>

static void xor_block(const unsigned char *a,
                      const unsigned char *b,
                      unsigned char *out,
                      int block_size)
{
    for (int i = 0; i < block_size; i++) {
        out[i] = (unsigned char)(a[i] ^ b[i]);
    }
}

static void pkcs7_add_block(unsigned char *block,
                            int used_bytes,
                            int block_size)
{
    unsigned char pad_len = (unsigned char)(block_size - used_bytes);
    for (int i = used_bytes; i < block_size; i++) {
        block[i] = pad_len;
    }
}

static int pkcs7_strip(unsigned char *data,
                       int in_len,
                       int block_size)
{
    if (in_len <= 0 || (in_len % block_size) != 0) {
        return -1;
    }

    unsigned char pad_len = data[in_len - 1];
    if (pad_len == 0 || pad_len > (unsigned char)block_size) {
        return -1;
    }

    for (int i = 0; i < (int)pad_len; i++) {
        if (data[in_len - 1 - i] != pad_len) {
            return -1;
        }
    }

    return in_len - (int)pad_len;
}

// ================= ENCRYPT =================
int cbc_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext)
{
    if (plaintext_len < 0) {
        return -1;
    }

    unsigned char prev_block[CBC_BLOCK_SIZE];
    unsigned char xored[CBC_BLOCK_SIZE];
    unsigned char last_block[CBC_BLOCK_SIZE];

    memcpy(prev_block, iv, CBC_BLOCK_SIZE);

    int full_blocks = plaintext_len / CBC_BLOCK_SIZE;
    int rem_bytes   = plaintext_len % CBC_BLOCK_SIZE;
    int out_offset  = 0;

    // Các block đầy đủ
    for (int i = 0; i < full_blocks; i++) {
        const unsigned char *plain_block = plaintext + i * CBC_BLOCK_SIZE;
        unsigned char *cipher_block      = ciphertext + out_offset;

        // X_i = P_i XOR C_{i-1} (C_0 = IV)
        xor_block(plain_block, prev_block, xored, CBC_BLOCK_SIZE);
        // C_i = E_k(X_i)
        aes_encrypt_block(key, xored, cipher_block);
        // chuẩn bị cho block sau
        memcpy(prev_block, cipher_block, CBC_BLOCK_SIZE);

        out_offset += CBC_BLOCK_SIZE;
    }

    // Block cuối + padding
    if (rem_bytes == 0) {
        // plaintext là bội số block -> thêm 1 block padding full
        for (int i = 0; i < CBC_BLOCK_SIZE; i++) {
            last_block[i] = (unsigned char)CBC_BLOCK_SIZE;
        }
    } else {
        // copy phần dư
        for (int i = 0; i < rem_bytes; i++) {
            last_block[i] = plaintext[full_blocks * CBC_BLOCK_SIZE + i];
        }
        // padding phần còn lại
        pkcs7_add_block(last_block, rem_bytes, CBC_BLOCK_SIZE);
    }

    // mã hoá block cuối
    xor_block(last_block, prev_block, xored, CBC_BLOCK_SIZE);
    aes_encrypt_block(key, xored, ciphertext + out_offset);
    out_offset += CBC_BLOCK_SIZE;

    return out_offset; // độ dài ciphertext
}

// ================= DECRYPT =================
int cbc_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext)
{
    if (ciphertext_len <= 0 || (ciphertext_len % CBC_BLOCK_SIZE) != 0) {
        return -1;
    }

    unsigned char prev_block[CBC_BLOCK_SIZE];
    unsigned char decrypted[CBC_BLOCK_SIZE];

    memcpy(prev_block, iv, CBC_BLOCK_SIZE);

    int num_blocks = ciphertext_len / CBC_BLOCK_SIZE;
    int out_offset = 0;

    for (int i = 0; i < num_blocks; i++) {
        const unsigned char *cipher_block = ciphertext + i * CBC_BLOCK_SIZE;
        unsigned char *plain_block        = plaintext + out_offset;

        // D_i = D_k(C_i)
        aes_decrypt_block(key, cipher_block, decrypted);
        // P_i' = D_i XOR C_{i-1} (C_0 = IV)
        xor_block(decrypted, prev_block, plain_block, CBC_BLOCK_SIZE);

        memcpy(prev_block, cipher_block, CBC_BLOCK_SIZE);
        out_offset += CBC_BLOCK_SIZE;
    }

    // bỏ padding
    int plain_len = pkcs7_strip(plaintext, out_offset, CBC_BLOCK_SIZE);
    if (plain_len < 0) {
        return -1;
    }
    return plain_len;
}
