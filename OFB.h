#ifndef OFB_H
#define OFB_H

// Block size 16 byte (AES-128)
#define OFB_BLOCK_SIZE 16

// ================== OFB không padding ==================
// Dùng như stream cipher, xử lý mọi độ dài
// key     : khoá
// iv      : 16 byte IV (O_0)
// input   : plaintext (khi mã hoá) hoặc ciphertext (khi giải mã)
// length  : độ dài dữ liệu (byte, >= 0)
// output  : buffer nhận dữ liệu ra
// return  : 0 nếu OK, -1 nếu lỗi (length < 0)
int ofb_crypt(const unsigned char *key,
              const unsigned char *iv,
              const unsigned char *input,
              int length,
              unsigned char *output);

// Wrapper cho đẹp tên
int ofb_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *plaintext,
                int plaintext_len,
                unsigned char *ciphertext);

int ofb_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *ciphertext,
                int ciphertext_len,
                unsigned char *plaintext);

// ================== OFB + PKCS#7 =======================
// Bản có padding PKCS#7 giống CBC_PKS7 để đồng bộ giao diện

// Mã hoá OFB + PKCS#7
// - plaintext_len bất kỳ (>= 0)
// - ciphertext_len trả về là bội số 16 (đã cộng padding)
int ofb_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext);

// Giải mã OFB + PKCS#7
// - ciphertext_len phải là bội số 16, > 0
// - trả về độ dài plaintext sau khi bỏ padding, hoặc -1 nếu lỗi
int ofb_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext);

#endif // OFB_H
