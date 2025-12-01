#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "ecb.h"
#include "cbc.h"
#include "ctr.h"
#include "ofb.h"

#define AES_BLOCK_SIZE 16
#define MAX_INPUT_LEN  1024

// ======= Helpers: HEX <-> bytes =======

static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// hex_str: chuỗi không có "0x", ví dụ "001122AABB"
// out: buffer nhận bytes
// max_out: kích thước buffer
// return: số byte convert được, hoặc -1 nếu lỗi
static int hex_string_to_bytes(const char *hex_str,
                               unsigned char *out,
                               int max_out)
{
    int len = (int)strlen(hex_str);
    if (len % 2 != 0) {
        return -1;
    }
    int out_len = len / 2;
    if (out_len > max_out) {
        return -1;
    }

    for (int i = 0; i < out_len; i++) {
        int hi = hex_char_to_val(hex_str[2 * i]);
        int lo = hex_char_to_val(hex_str[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return out_len;
}

static void bytes_to_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


static void read_line(char *buf, int max_len)
{
    if (fgets(buf, max_len, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    size_t l = strlen(buf);
    if (l > 0 && buf[l - 1] == '\n') {
        buf[l - 1] = '\0';
    }
}

// ======= MAIN =======

int main(void)
{
    int mode_choice;
    int input_format;

    printf("=== AES Block Cipher Modes ===\n");
    printf("1. ECB\n");
    printf("2. CBC\n");
    printf("3. CTR\n");
    printf("4. OFB\n");
    printf("Chon mode (1-4): ");

    if (scanf("%d", &mode_choice) != 1) {
        printf("Nhap loi.\n");
        return 1;
    }

    // clear newline còn lại trong stdin
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    if (mode_choice < 1 || mode_choice > 4) {
        printf("Mode khong hop le.\n");
        return 1;
    }

    printf("Chon kieu nhap plaintext:\n");
    printf("1. ASCII\n");
    printf("2. HEX (khong co 0x, vi du: 48656C6C6F)\n");
    printf("Lua chon (1-2): ");
    if (scanf("%d", &input_format) != 1) {
        printf("Nhap loi.\n");
        return 1;
    }
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    if (input_format != 1 && input_format != 2) {
        printf("Lua chon khong hop le.\n");
        return 1;
    }

    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext[MAX_INPUT_LEN + AES_BLOCK_SIZE];   // dư cho padding
    unsigned char ciphertext[MAX_INPUT_LEN + 2 * AES_BLOCK_SIZE];

    int plaintext_len = 0;
    int ciphertext_len = 0;

    char line_buf[2 * MAX_INPUT_LEN + 4];

    // ====== Nhap key (HEX) ======
    printf("Nhap key (128-bit, 32 hex, vd: 00112233445566778899AABBCCDDEEFF):\n");
    read_line(line_buf, sizeof(line_buf));

    int key_len = hex_string_to_bytes(line_buf, key, AES_BLOCK_SIZE);
    if (key_len != AES_BLOCK_SIZE) {
        printf("Key khong hop le (phai 16 byte).\n");
        return 1;
    }

    // ====== Nhap IV / Nonce neu can ======
    if (mode_choice == 2 || mode_choice == 3 || mode_choice == 4) {
        printf("Nhap IV / nonce (128-bit, 32 hex):\n");
        read_line(line_buf, sizeof(line_buf));
        int iv_len = hex_string_to_bytes(line_buf, iv, AES_BLOCK_SIZE);
        if (iv_len != AES_BLOCK_SIZE) {
            printf("IV khong hop le (phai 16 byte).\n");
            return 1;
        }
    }

    // ====== Nhap plaintext (ASCII hoac HEX) ======
    if (input_format == 1) {
        // ASCII
        printf("Nhap plaintext (ASCII):\n");
        read_line(line_buf, sizeof(line_buf));
        plaintext_len = (int)strlen(line_buf);
        if (plaintext_len > MAX_INPUT_LEN) {
            printf("Plaintext qua dai.\n");
            return 1;
        }
        memcpy(plaintext, line_buf, plaintext_len);
    } else {
        // HEX
        printf("Nhap plaintext (HEX, khong co 0x, so byte <= %d):\n", MAX_INPUT_LEN);
        read_line(line_buf, sizeof(line_buf));
        int len = hex_string_to_bytes(line_buf, plaintext, MAX_INPUT_LEN);
        if (len < 0) {
            printf("Plaintext HEX khong hop le.\n");
            return 1;
        }
        plaintext_len = len;
    }

    // ====== Encrypt theo mode ======
    int ok;

    switch (mode_choice) {
    case 1: { // ECB (PKCS7) - dùng encrypt_ecb trong ecb.c
        int out_len = 0;
        ok = encrypt_ecb(
            (const uint8_t *)key,
            (uint8_t *)plaintext,
            plaintext_len,
            (uint8_t *)ciphertext,
            AES_BLOCK_SIZE,
            (int *)&out_len
        );
        if (!ok) {
            printf("Loi ma hoa ECB.\n");
            return 1;
        }
        ciphertext_len = out_len;
        break;
    }
    case 2: { // CBC + PKCS7
        ciphertext_len = cbc_encrypt_pkcs7(
            key,
            iv,
            plaintext,
            plaintext_len,
            ciphertext
        );
        if (ciphertext_len < 0) {
            printf("Loi ma hoa CBC.\n");
            return 1;
        }
        break;
    }
    case 3: { // CTR (khong padding)
        ciphertext_len = ctr_encrypt(
            key,
            iv,
            plaintext,
            plaintext_len,
            ciphertext
        );
        if (ciphertext_len < 0) {
            printf("Loi ma hoa CTR.\n");
            return 1;
        }
        break;
    }
    case 4: { // OFB + PKCS7
        ciphertext_len = ofb_encrypt_pkcs7(
            key,
            iv,
            plaintext,
            plaintext_len,
            ciphertext
        );
        if (ciphertext_len < 0) {
            printf("Loi ma hoa OFB.\n");
            return 1;
        }
        break;
    }
    default:
        printf("Mode khong ho tro.\n");
        return 1;
    }

    // ====== In ket qua ======
    printf("Ciphertext (HEX):\n");
    bytes_to_hex(ciphertext, ciphertext_len);

    return 0;
}
