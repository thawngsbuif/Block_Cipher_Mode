#ifndef CTR_H
#define CTR_H

#define CTR_BLOCK_SIZE 16

// Mã hoá CTR
// - Không dùng padding, chiều dài input = output.
// - return: số byte output (>= 0) hoặc -1 nếu lỗi.
int ctr_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output);

// Giải mã CTR (thực chất giống hệt mã hoá).
// - return: số byte output (>= 0) hoặc -1 nếu lỗi.
int ctr_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output);

#endif // CTR_H
