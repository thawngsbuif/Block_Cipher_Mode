#include "ctr.h"
#include "aes.h"
#include <string.h>

// Tăng counter 128-bit (big-endian) thêm 1
static void ctr_increment(unsigned char *counter, int block_size)
{
    for (int i = block_size - 1; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) {
            // không còn carry nữa
            break;
        }
    }
}

// Hàm dùng chung cho cả encrypt/decrypt (CTR đối xứng)
static int ctr_crypt(const unsigned char *key,
                     const unsigned char *iv,
                     const unsigned char *input,
                     int input_len,
                     unsigned char *output)
{
    if (input_len < 0) {
        return -1;
    }

    unsigned char counter[CTR_BLOCK_SIZE];
    unsigned char keystream[CTR_BLOCK_SIZE];

    // Khởi tạo counter từ IV (nonce || initial counter)
    memcpy(counter, iv, CTR_BLOCK_SIZE);

    int offset = 0;
    while (offset < input_len) {
        int block_len = input_len - offset;
        if (block_len > CTR_BLOCK_SIZE) {
            block_len = CTR_BLOCK_SIZE;
        }

        // Keystream = AES_encrypt(counter)
        aes_encrypt_block(key, counter, keystream);

        // XOR input với keystream => output
        for (int i = 0; i < block_len; i++) {
            output[offset + i] =
                (unsigned char)(input[offset + i] ^ keystream[i]);
        }

        // Tăng counter cho block tiếp theo
        ctr_increment(counter, CTR_BLOCK_SIZE);
        offset += block_len;
    }

    return input_len;
}

int ctr_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output)
{
    return ctr_crypt(key, iv, input, input_len, output);
}

int ctr_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *input,
                int input_len,
                unsigned char *output)
{
    return ctr_crypt(key, iv, input, input_len, output);
}
