#include <stdio.h>
#include <string.h>

void xor_block(unsigned char *a, unsigned char *b, unsigned char *out, int block_size) {
    for (int i = 0; i < block_size; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void increase_counter(unsigned char *counter, int block_size) {
    for (int i = block_size - 1; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break;
    }
}

void encrypt_ctr(unsigned char *key, unsigned char *nonce, unsigned char *plaintext,
                 int plaintext_len, unsigned char *ciphertext, int block_size) {

    unsigned char counter[64];
    unsigned char keystream[64];

    memcpy(counter, nonce, block_size); 
    int num_blocks = (plaintext_len + block_size - 1) / block_size;

    for (int i = 0; i < num_blocks; i++) {
        // Trong ví dụ này dùng XOR(counter, key) làm "block cipher"
        xor_block(counter, key, keystream, block_size);

        int chunk = block_size;
        if (i == num_blocks - 1 && plaintext_len % block_size != 0)
            chunk = plaintext_len % block_size;

        xor_block(plaintext + i * block_size, keystream, ciphertext + i * block_size, chunk);
        increase_counter(counter, block_size);
    }
}

int main() {
    const int block_size = 16;

    unsigned char key_input[256];
    unsigned char nonce_input[256];
    unsigned char plaintext[256];

    unsigned char key[16];
    unsigned char nonce[16];

    unsigned char ciphertext[256];
    unsigned char decrypted[256];

    // Đọc key
    printf("Nhap key (toi da 16 ky tu): ");
    if (fgets((char*)key_input, sizeof(key_input), stdin) == NULL) {
        printf("Loi khi nhap key.\n");
        return 1;
    }
    // Bỏ ký tự xuống dòng
    size_t len = strlen((char*)key_input);
    if (len > 0 && key_input[len - 1] == '\n') {
        key_input[len - 1] = '\0';
        len--;
    }

    // Copy vào mảng key 16 byte, nếu thiếu thì pad 0
    memset(key, 0, block_size);
    if (len > block_size) len = block_size;
    memcpy(key, key_input, len);

    // Đọc nonce
    printf("Nhap nonce (toi da 16 ky tu): ");
    if (fgets((char*)nonce_input, sizeof(nonce_input), stdin) == NULL) {
        printf("Loi khi nhap nonce.\n");
        return 1;
    }
    len = strlen((char*)nonce_input);
    if (len > 0 && nonce_input[len - 1] == '\n') {
        nonce_input[len - 1] = '\0';
        len--;
    }

    memset(nonce, 0, block_size);
    if (len > block_size) len = block_size;
    memcpy(nonce, nonce_input, len);

    // Đọc plaintext (cho phép có dấu cách)
    printf("Nhap plaintext: ");
    if (fgets((char*)plaintext, sizeof(plaintext), stdin) == NULL) {
        printf("Loi khi nhap plaintext.\n");
        return 1;
    }
    int text_len = (int)strlen((char*)plaintext);
    if (text_len > 0 && plaintext[text_len - 1] == '\n') {
        plaintext[text_len - 1] = '\0';
        text_len--;
    }

    printf("Plaintext: %s\n", plaintext);

    // Mã hóa
    encrypt_ctr(key, nonce, plaintext, text_len, ciphertext, block_size);

    printf("Ciphertext (hex): ");
    for (int i = 0; i < text_len; i++)
        printf("%02X", ciphertext[i]);
    printf("\n");

    // Giải mã (CTR: mã hóa lần nữa là ra plaintext)
    encrypt_ctr(key, nonce, ciphertext, text_len, decrypted, block_size);
    decrypted[text_len] = '\0';

    printf("Decrypted: %s\n", decrypted);

    return 0;
}
