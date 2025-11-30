#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "aes.h"
#include "cbc.h"

#define MAX_PLAINTEXT_LEN   1024
#define MAX_CIPHERTEXT_LEN  (MAX_PLAINTEXT_LEN + CBC_BLOCK_SIZE)

// ======== HÀM PHỤ TRỢ ========

static int hex_char_to_val(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void remove_spaces(char *s)
{
    int w = 0;
    for (int r = 0; s[r] != '\0'; r++) {
        if (!isspace((unsigned char)s[r])) {
            s[w++] = s[r];
        }
    }
    s[w] = '\0';
}

// hex string -> bytes
static int hex_string_to_bytes(const char *hex_str,
                               unsigned char *out,
                               int *out_len)
{
    int len = (int)strlen(hex_str);
    if (len == 0 || (len % 2) != 0) {
        return -1;
    }

    int bytes = len / 2;
    for (int i = 0; i < bytes; i++) {
        int hi = hex_char_to_val(hex_str[2*i]);
        int lo = hex_char_to_val(hex_str[2*i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = bytes;
    return 0;
}

static void print_hex(const char *label,
                      const unsigned char *data,
                      int len)
{
    printf("%s", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void read_line(char *buf, int buf_size)
{
    if (fgets(buf, buf_size, stdin) != NULL) {
        int len = (int)strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
    }
}

// ======== MAIN ========

int main(void)
{
    char key_hex[128];
    char iv_hex[128];
    char choice[8];

    char plaintext_ascii[MAX_PLAINTEXT_LEN + 1];
    char plaintext_hex_input[2*MAX_PLAINTEXT_LEN + 4];

    unsigned char key[16];
    unsigned char iv[16];
    int key_len = 0;
    int iv_len  = 0;

    unsigned char plaintext_bytes[MAX_PLAINTEXT_LEN + 1];
    int plaintext_len = 0;

    unsigned char ciphertext[MAX_CIPHERTEXT_LEN];
    unsigned char decrypted[MAX_PLAINTEXT_LEN + CBC_BLOCK_SIZE];
    int ct_len, pt_len;

    printf("=== AES-128 CBC mode (PKCS#7) ===\n\n");

    // --- Key ---
    printf("Nhap key 128-bit (32 ky tu hex, vd: 2b7e151628aed2a6abf7158809cf4f3c)\n");
    printf("> ");
    read_line(key_hex, sizeof(key_hex));
    remove_spaces(key_hex);

    if (hex_string_to_bytes(key_hex, key, &key_len) != 0 || key_len != 16) {
        printf("Loi: key khong hop le. Can 32 ky tu hex (=16 byte).\n");
        return 1;
    }

    // --- IV ---
    printf("\nNhap IV 128-bit (32 ky tu hex, vd: 000102030405060708090a0b0c0d0e0f)\n");
    printf("> ");
    read_line(iv_hex, sizeof(iv_hex));
    remove_spaces(iv_hex);

    if (hex_string_to_bytes(iv_hex, iv, &iv_len) != 0 || iv_len != 16) {
        printf("Loi: IV khong hop le. Can 32 ky tu hex (=16 byte).\n");
        return 1;
    }

    // --- Chọn kiểu plaintext ---
    printf("\nChon kieu nhap plaintext:\n");
    printf("  1 - ASCII (chuoi ky tu binh thuong)\n");
    printf("  2 - Hex (chuoi hex, vd: 00112233aabbcc)\n");
    printf("> ");
    read_line(choice, sizeof(choice));

    if (choice[0] == '1') {
        // ASCII
        printf("\nNhap plaintext (ASCII), vd: Hello CBC!\n");
        printf("> ");
        read_line(plaintext_ascii, sizeof(plaintext_ascii));
        plaintext_len = (int)strlen(plaintext_ascii);

        if (plaintext_len <= 0) {
            printf("Loi: plaintext rong.\n");
            return 1;
        }
        if (plaintext_len > MAX_PLAINTEXT_LEN) {
            printf("Loi: plaintext qua dai (max %d byte).\n", MAX_PLAINTEXT_LEN);
            return 1;
        }

        memcpy(plaintext_bytes, plaintext_ascii, plaintext_len);

    } else if (choice[0] == '2') {
        // Hex
        printf("\nNhap plaintext (hex, co the cach bang dau cach), vd: 00112233aabbcc\n");
        printf("> ");
        read_line(plaintext_hex_input, sizeof(plaintext_hex_input));
        remove_spaces(plaintext_hex_input);

        if (hex_string_to_bytes(plaintext_hex_input,
                                plaintext_bytes,
                                &plaintext_len) != 0)
        {
            printf("Loi: plaintext hex khong hop le (do dai le hoac ky tu khong phai hex).\n");
            return 1;
        }

        if (plaintext_len <= 0) {
            printf("Loi: plaintext rong.\n");
            return 1;
        }
        if (plaintext_len > MAX_PLAINTEXT_LEN) {
            printf("Loi: plaintext qua dai (max %d byte).\n", MAX_PLAINTEXT_LEN);
            return 1;
        }

    } else {
        printf("Lua chon khong hop le.\n");
        return 1;
    }

    // --- Encrypt CBC+PKCS7 ---
    ct_len = cbc_encrypt_pkcs7(key, iv,
                               plaintext_bytes,
                               plaintext_len,
                               ciphertext);
    if (ct_len < 0) {
        printf("Loi: cbc_encrypt_pkcs7 that bai.\n");
        return 1;
    }

    print_hex("\nCiphertext (hex): ", ciphertext, ct_len);

    // --- Decrypt để kiểm tra ---
    pt_len = cbc_decrypt_pkcs7(key, iv,
                               ciphertext,
                               ct_len,
                               decrypted);
    if (pt_len < 0) {
        printf("Loi: cbc_decrypt_pkcs7 that bai (padding sai?)\n");
        return 1;
    }

    printf("Plaintext giai ma lai:\n");
    if (choice[0] == '1') {
        // ban đầu nhập ASCII => in lại ASCII + hex
        if (pt_len < MAX_PLAINTEXT_LEN) {
            decrypted[pt_len] = '\0';
        } else {
            decrypted[MAX_PLAINTEXT_LEN] = '\0';
        }
        printf("  ASCII: %s\n", decrypted);
        print_hex("  HEX  : ", decrypted, pt_len);
    } else {
        // ban đầu nhập hex => in lại hex
        print_hex("  HEX  : ", decrypted, pt_len);
    }

    printf("\nHoan tat.\n");
    return 0;
}
