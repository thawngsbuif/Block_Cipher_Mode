#ifndef AES_H
#define AES_H

// mã hoá 1 block 16 byte với AES-128
void aes_encrypt_block(const unsigned char *key,
                       const unsigned char *in,
                       unsigned char *out);

// giải mã 1 block 16 byte với AES-128
void aes_decrypt_block(const unsigned char *key,
                       const unsigned char *in,
                       unsigned char *out);

#endif
