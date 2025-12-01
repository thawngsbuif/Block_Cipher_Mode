#ifndef CTR_H
#define CTR_H

#define CTR_BLOCK_SIZE 16

// Mã hoá CTR

int ctr_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output);

// Giải mã CTR
int ctr_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output);

#endif 
