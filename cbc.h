#ifndef CBC_H
#define CBC_H

#define CBC_BLOCK_SIZE 16

// Mã hoá CBC với PKCS#7
int cbc_encrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *plaintext,
                      int plaintext_len,
                      unsigned char *ciphertext);

// Giải mã CBC với PKCS#7
int cbc_decrypt_pkcs7(const unsigned char *key,
                      const unsigned char *iv,
                      const unsigned char *ciphertext,
                      int ciphertext_len,
                      unsigned char *plaintext);

#endif 
