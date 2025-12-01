#ifndef OFB_H
#define OFB_H

#define OFB_BLOCK_SIZE 16  // 128-bit block

// AES-128 OFB + PKCS#7
// return: độ dài ciphertext (>0) hoặc -1 nếu lỗi
int ofb_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext);

// AES-128 OFB + PKCS#7
// return: độ dài plaintext (>=0) hoặc -1 nếu lỗi/padding sai
int ofb_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext);

#endif // OFB_H
