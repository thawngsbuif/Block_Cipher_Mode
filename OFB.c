#include "ofb.h"
#include <string.h> // memcpy

// ======================================================
// (AES, DES,...). OFB chỉ cần encrypt.
// ======================================================
void block_encrypt(const unsigned char *key,
                   const unsigned char *in,
                   unsigned char *out);

// XOR 2 block: out = a XOR b
static void xor_block(const unsigned char *a,
                      const unsigned char *b,
                      unsigned char *out,
                      int block_size)
{
    for (int i = 0; i < block_size; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// ================== OFB CORE (KHÔNG PADDING) ===========
// O_0 = IV
// O_i = E_k(O_{i-1})
// output_i = input_i XOR O_i
int ofb_crypt(const unsigned char *key,
              const unsigned char *iv,
              const unsigned char *input,
              int length,
              unsigned char *output)
{
    if (length < 0) {
        return -1;
    }

    unsigned char ofb_block[OFB_BLOCK_SIZE];   // O_i
    unsigned char keystream[OFB_BLOCK_SIZE];   // E_k(O_{i-1})

    // Khởi tạo O_0 = IV
    memcpy(ofb_block, iv, OFB_BLOCK_SIZE);

    int full_blocks = length / OFB_BLOCK_SIZE;
    int rem_bytes   = length % OFB_BLOCK_SIZE;

    int offset = 0;

    // 1. Xử lý các block đầy đủ 16 byte
    for (int i = 0; i < full_blocks; i++) {
        const unsigned char *in_block  = input  + offset;
        unsigned char       *out_block = output + offset;

        // O_i = E_k(O_{i-1})
        block_encrypt(key, ofb_block, keystream);

        // output_i = input_i XOR O_i
        xor_block(in_block, keystream, out_block, OFB_BLOCK_SIZE);

        // Cập nhật O_{i-1} = O_i
        memcpy(ofb_block, keystream, OFB_BLOCK_SIZE);

        offset += OFB_BLOCK_SIZE;
    }

    // 2. Xử lý phần dư (< 16 byte)
    if (rem_bytes > 0) {
        // Tạo thêm một block keystream
        block_encrypt(key, ofb_block, keystream);

        for (int i = 0; i < rem_bytes; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
    }

    return 0;
}

// =============== Wrapper ENCRYPT/DECRYPT (no pad) ======

int ofb_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *plaintext,
                int plaintext_len,
                unsigned char *ciphertext)
{
    return ofb_crypt(key, iv, plaintext, plaintext_len, ciphertext);
}

int ofb_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *ciphertext,
                int ciphertext_len,
                unsigned char *plaintext)
{
    // OFB: giải mã = mã hoá
    return ofb_crypt(key, iv, ciphertext, ciphertext_len, plaintext);
}

// ================== PKCS#7 HELPER ======================

// Thêm padding PKCS#7 vào block cuối
// block      : mảng 16 byte
// used_bytes : số byte dữ liệu thật trong block (0..15)
static void pkcs7_add_block(unsigned char *block,
                            int used_bytes,
                            int block_size)
{
    unsigned char pad_len = (unsigned char)(block_size - used_bytes);

    for (int i = used_bytes; i < block_size; i++) {
        block[i] = pad_len;
    }
}

// Bỏ padding PKCS#7 tại cuối buffer
// data   : buffer chứa nhiều block (plaintext đã giải OFB)
// in_len : độ dài buffer (bội số block_size)
// return : độ dài sau khi bỏ padding, -1 nếu padding sai
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

    // kiểm tra pad_len byte cuối đều bằng pad_len
    for (int i = 0; i < (int)pad_len; i++) {
        if (data[in_len - 1 - i] != pad_len) {
            return -1;
        }
    }

    return in_len - (int)pad_len;
}

// ============== OFB ENCRYPT + PKCS#7 ===================
// plaintext_len bất kỳ (>= 0)
// ciphertext_len trả về = (số block sau padding)*16
int ofb_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext)
{
    if (plaintext_len < 0) {
        return -1;
    }

    unsigned char ofb_block[OFB_BLOCK_SIZE];
    unsigned char keystream[OFB_BLOCK_SIZE];
    unsigned char last_block[OFB_BLOCK_SIZE];

    memcpy(ofb_block, iv, OFB_BLOCK_SIZE);

    int full_blocks = plaintext_len / OFB_BLOCK_SIZE;
    int rem_bytes   = plaintext_len % OFB_BLOCK_SIZE;

    int offset = 0;

    // 1. Xử lý các block đầy đủ (không dính padding)
    for (int i = 0; i < full_blocks; i++) {
        const unsigned char *in_block  = plaintext + offset;
        unsigned char       *out_block = ciphertext + offset;

        // O_i = E_k(O_{i-1})
        block_encrypt(key, ofb_block, keystream);

        // output_i = input_i XOR O_i
        xor_block(in_block, keystream, out_block, OFB_BLOCK_SIZE);

        // O_{i-1} = O_i
        memcpy(ofb_block, keystream, OFB_BLOCK_SIZE);

        offset += OFB_BLOCK_SIZE;
    }

    // 2. Tạo block cuối đã padding
    if (rem_bytes == 0) {
        // Trường hợp chia hết 16: thêm 1 block padding full
        for (int i = 0; i < OFB_BLOCK_SIZE; i++) {
            last_block[i] = (unsigned char)OFB_BLOCK_SIZE;
        }
    } else {
        // Có phần dư: copy rem_bytes vào đầu block
        for (int i = 0; i < rem_bytes; i++) {
            last_block[i] = plaintext[full_blocks * OFB_BLOCK_SIZE + i];
        }
        // Padding phần còn lại
pkcs7_add_block(last_block, rem_bytes, OFB_BLOCK_SIZE);
    }

    // Tạo keystream cho block cuối
    block_encrypt(key, ofb_block, keystream);

    // XOR last_block với keystream
    xor_block(last_block, keystream, ciphertext + offset, OFB_BLOCK_SIZE);
    offset += OFB_BLOCK_SIZE;

    // offset = tổng độ dài ciphertext sau padding
    return offset;
}

// ============== OFB DECRYPT + PKCS#7 ===================
// ciphertext_len: bội số 16, > 0
// plaintext: phải đủ lớn để chứa ciphertext_len
int ofb_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext)
{
    if (ciphertext_len <= 0 || (ciphertext_len % OFB_BLOCK_SIZE) != 0) {
        return -1;
    }

    unsigned char ofb_block[OFB_BLOCK_SIZE];
    unsigned char keystream[OFB_BLOCK_SIZE];

    memcpy(ofb_block, iv, OFB_BLOCK_SIZE);

    int num_blocks = ciphertext_len / OFB_BLOCK_SIZE;
    int offset     = 0;

    // 1. Giải OFB giống mã hoá: tạo keystream & XOR
    for (int i = 0; i < num_blocks; i++) {
        const unsigned char *in_block  = ciphertext + offset;
        unsigned char       *out_block = plaintext  + offset;

        // O_i = E_k(O_{i-1})
        block_encrypt(key, ofb_block, keystream);

        // plaintext_i' (có padding) = C_i XOR O_i
        xor_block(in_block, keystream, out_block, OFB_BLOCK_SIZE);

        // O_{i-1} = O_i
        memcpy(ofb_block, keystream, OFB_BLOCK_SIZE);

        offset += OFB_BLOCK_SIZE;
    }

    // 2. Bỏ padding PKCS#7 trên toàn buffer plaintext
    int plain_len = pkcs7_strip(plaintext, offset, OFB_BLOCK_SIZE);
    if (plain_len < 0) {
        return -1;
    }

    return plain_len;
}
