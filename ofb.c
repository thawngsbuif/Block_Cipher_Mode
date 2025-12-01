#include "ofb.h"
#include "aes.h"
#include <string.h>

// ================= HÀM PHỤ TRỢ  =================

static void xor_block(const unsigned char *a,
                      const unsigned char *b,
                      unsigned char *out,
                      int block_size)
{
    for (int i = 0; i < block_size; i++) {
        out[i] = (unsigned char)(a[i] ^ b[i]);
    }
}

// Thêm padding PKCS#7 vào block cuối
static void pkcs7_add_block(unsigned char *block,
                            int used_bytes,
                            int block_size)
{
    unsigned char pad_len = (unsigned char)(block_size - used_bytes);
    for (int i = used_bytes; i < block_size; i++) {
        block[i] = pad_len;
    }
}

// Bỏ padding PKCS#7
// return: độ dài mới hoặc -1 nếu padding không hợp lệ
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

// ================= ENCRYPT (OFB + PKCS#7) =================

int ofb_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext)
{
    if (plaintext_len < 0) {
        return -1;
    }

    unsigned char ofb_state[OFB_BLOCK_SIZE];   // giữ giá trị "OFB state" hiện tại
    unsigned char keystream[OFB_BLOCK_SIZE];   // AES(key, ofb_state)
    unsigned char last_block[OFB_BLOCK_SIZE];

    memcpy(ofb_state, iv, OFB_BLOCK_SIZE);

    int full_blocks = plaintext_len / OFB_BLOCK_SIZE;
    int rem_bytes   = plaintext_len % OFB_BLOCK_SIZE;
    int out_offset  = 0;

    // Các block đầy đủ
    for (int i = 0; i < full_blocks; i++) {
        const unsigned char *plain_block = plaintext + i * OFB_BLOCK_SIZE;
        unsigned char *cipher_block      = ciphertext + out_offset;

        // KS_i = E_k(OFB_state)
        aes_encrypt_block(key, ofb_state, keystream);
        // C_i = P_i XOR KS_i
        xor_block(plain_block, keystream, cipher_block, OFB_BLOCK_SIZE);
        // OFB_state = KS_i
        memcpy(ofb_state, keystream, OFB_BLOCK_SIZE);

        out_offset += OFB_BLOCK_SIZE;
    }

    // Block cuối + padding PKCS#7 
    if (rem_bytes == 0) {
        // plaintext là bội số block -> thêm 1 block padding full
        for (int i = 0; i < OFB_BLOCK_SIZE; i++) {
            last_block[i] = (unsigned char)OFB_BLOCK_SIZE;
        }
    } else {
        // copy phần dư
        for (int i = 0; i < rem_bytes; i++) {
            last_block[i] = plaintext[full_blocks * OFB_BLOCK_SIZE + i];
        }
        // padding phần còn lại
        pkcs7_add_block(last_block, rem_bytes, OFB_BLOCK_SIZE);
    }

    // Mã hoá block cuối
    aes_encrypt_block(key, ofb_state, keystream);
    xor_block(last_block, keystream, ciphertext + out_offset, OFB_BLOCK_SIZE);
    // OFB_state = keystream (không thật sự cần sau block cuối, nhưng để code đúng logic)
    memcpy(ofb_state, keystream, OFB_BLOCK_SIZE);

    out_offset += OFB_BLOCK_SIZE;

    return out_offset; // độ dài ciphertext
}

// ================= DECRYPT (OFB + PKCS#7) =================

int ofb_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext)
{
    if (ciphertext_len <= 0 || (ciphertext_len % OFB_BLOCK_SIZE) != 0) {
        return -1;
    }

    unsigned char ofb_state[OFB_BLOCK_SIZE];
    unsigned char keystream[OFB_BLOCK_SIZE];

    memcpy(ofb_state, iv, OFB_BLOCK_SIZE);

    int num_blocks = ciphertext_len / OFB_BLOCK_SIZE;
    int out_offset = 0;

    for (int i = 0; i < num_blocks; i++) {
        const unsigned char *cipher_block = ciphertext + i * OFB_BLOCK_SIZE;
        unsigned char *plain_block        = plaintext + out_offset;

        // KS_i = E_k(OFB_state)
        aes_encrypt_block(key, ofb_state, keystream);
        // P_i' = C_i XOR KS_i
        xor_block(cipher_block, keystream, plain_block, OFB_BLOCK_SIZE);
        // OFB_state = KS_i
        memcpy(ofb_state, keystream, OFB_BLOCK_SIZE);

        out_offset += OFB_BLOCK_SIZE;
    }

    // Bỏ padding PKCS#7
    int plain_len = pkcs7_strip(plaintext, out_offset, OFB_BLOCK_SIZE);
    if (plain_len < 0) {
        return -1;
    }
    return plain_len;
}
