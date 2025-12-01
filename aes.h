#ifndef AES_H
#define AES_H

// AES-128: key 16 byte, block 16 byte
void aes_encrypt_block(const unsigned char *key,
                       const unsigned char *in,
                       unsigned char *out);

void aes_decrypt_block(const unsigned char *key,
                       const unsigned char *in,
                       unsigned char *out);

#endif // AES_H