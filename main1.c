#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "aes.h"
#include "cbc.h"
#include "ctr.h"

#define MAX_PLAINTEXT_LEN   1024
#define MAX_CIPHERTEXT_LEN  (MAX_PLAINTEXT_LEN + CBC_BLOCK_SIZE)

// ======== HÀM PHỤ TRỢ ========

// chuyển 1 ký tự hex sang giá trị 0..15
static int hex_char_to_val(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// loại bỏ khoảng trắng trong chuỗi (in-place)
static void remove_spaces(char *s)
{
    char *d = s;
    while (*s) {
        if (!isspace((unsigned char)*s)) {
            *d++ = *s;
        }
        s++;
    }
    *d = '\0';
}

// chuyển chuỗi hex sang mảng byte
// - hex_str: chuỗi chỉ chứa [0-9a-fA-F], length chẵn
// - out: buffer nhận kết quả
// - out_len: trả về số byte
// - return: 0 nếu ok, -1 nếu lỗi
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

// in mảng byte dạng hex
static void print_hex(const char *prefix,
                      const unsigned char *buf,
                      int len)
{
    if (prefix) {
        printf("%s", prefix);
    }
    for (int i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

// đọc 1 dòng từ stdin, bỏ newline ở cuối (nếu có)
static void read_line(char *buf, int buf_size)
{
    if (fgets(buf, buf_size, stdin) != NULL) {
        size_t l = strlen(buf);
        if (l > 0 && (buf[l-1] == '\n' || buf[l-1] == '\r')) {
            buf[l-1] = '\0';
            if (l > 1 && buf[l-2] == '\r') {
                buf[l-2] = '\0';
            }
        }
    } else {
        // EOF hoặc lỗi => chuỗi rỗng
        buf[0] = '\0';
    }
}

// ======== MAIN ========

int main(void)
{
    unsigned char key[16];
    unsigned char iv[16];

    char input_line[4096];
    char hex_tmp[4096];

    unsigned char plaintext_bytes[MAX_PLAINTEXT_LEN];
    unsigned char ciphertext[MAX_CIPHERTEXT_LEN];
    unsigned char decrypted[MAX_PLAINTEXT_LEN + CBC_BLOCK_SIZE]; // đủ cho cả CBC sau unpad

    int plaintext_len = 0;
    int ct_len = 0;
    int pt_len = 0;

    int mode = 0;          // 1 = CBC, 2 = CTR
    int plaintext_is_ascii = 0;

    printf("=== DEMO AES-128 CBC / CTR ===\n\n");

    // ========== NHẬP KEY ==========
    printf("Nhap key (hex 32 ki tu, khong hoac co dau cach):\n> ");
    read_line(input_line, sizeof(input_line));
    remove_spaces(input_line);

    int key_len = 0;
    if (hex_string_to_bytes(input_line, key, &key_len) != 0 || key_len != 16) {
        printf("Key khong hop le. Can 16 byte (32 hex).\n");
        return 1;
    }

    // ========== NHẬP IV ==========
    printf("\nNhap IV (hex 32 ki tu, khong hoac co dau cach):\n> ");
    read_line(input_line, sizeof(input_line));
    remove_spaces(input_line);

    int iv_len = 0;
    if (hex_string_to_bytes(input_line, iv, &iv_len) != 0 || iv_len != 16) {
        printf("IV khong hop le. Can 16 byte (32 hex).\n");
        return 1;
    }

    // ========== CHỌN MODE ==========
    printf("\nChon che do ma hoa:\n");
    printf("  1) CBC (PKCS#7)\n");
    printf("  2) CTR\n");
    printf("Nhap lua chon (1/2): ");
    read_line(input_line, sizeof(input_line));
    mode = atoi(input_line);
    if (mode != 1 && mode != 2) {
        printf("Lua chon mode khong hop le.\n");
        return 1;
    }

    // ========== CHỌN ĐỊNH DẠNG PLAINTEXT ==========
    printf("\nChon dinh dang plaintext:\n");
    printf("  1) ASCII text\n");
    printf("  2) HEX\n");
    printf("Nhap lua chon (1/2): ");
    read_line(input_line, sizeof(input_line));
    int pt_fmt = atoi(input_line);
    if (pt_fmt == 1) {
        plaintext_is_ascii = 1;
    } else if (pt_fmt == 2) {
        plaintext_is_ascii = 0;
    } else {
        printf("Lua chon dinh dang khong hop le.\n");
        return 1;
    }

    // ========== NHẬP PLAINTEXT ==========
    if (plaintext_is_ascii) {
        printf("\nNhap plaintext (ASCII), toi da %d ky tu:\n> ",
               MAX_PLAINTEXT_LEN);
        read_line(input_line, sizeof(input_line));
        plaintext_len = (int)strlen(input_line);
        if (plaintext_len > MAX_PLAINTEXT_LEN) {
            printf("Plaintext qua dai.\n");
            return 1;
        }
        memcpy(plaintext_bytes, input_line, plaintext_len);
    } else {
        printf("\nNhap plaintext (hex, co the cach bang dau cach), "
               "toi da %d byte:\n> ",
               MAX_PLAINTEXT_LEN);
        read_line(input_line, sizeof(input_line));
        remove_spaces(input_line);

        int tmp_len = 0;
        if (hex_string_to_bytes(input_line,
                                plaintext_bytes,
                                &tmp_len) != 0) {
            printf("Plaintext hex khong hop le.\n");
            return 1;
        }
        if (tmp_len > MAX_PLAINTEXT_LEN) {
            printf("Plaintext qua dai.\n");
            return 1;
        }
        plaintext_len = tmp_len;
    }

    // ========== MÃ HOÁ ==========
    printf("\nDang ma hoa...\n");

    if (mode == 1) {
        // CBC + PKCS#7
        ct_len = cbc_encrypt_pkcs7(key, iv,
                                   plaintext_bytes, plaintext_len,
                                   ciphertext);
        if (ct_len < 0) {
            printf("Loi ma hoa CBC.\n");
            return 1;
        }
        printf("Che do: CBC (PKCS#7)\n");
    } else {
        // CTR
        ct_len = ctr_encrypt(key, iv,
                             plaintext_bytes, plaintext_len,
                             ciphertext);
        if (ct_len < 0) {
            printf("Loi ma hoa CTR.\n");
            return 1;
        }
        printf("Che do: CTR\n");
    }

    print_hex("Ciphertext (HEX): ", ciphertext, ct_len);

    // ========== GIẢI MÃ ĐỂ KIỂM TRA ==========
    printf("\nDang giai ma de kiem tra...\n");

    if (mode == 1) {
        pt_len = cbc_decrypt_pkcs7(key, iv,
                                   ciphertext, ct_len,
                                   decrypted);
        if (pt_len < 0) {
            printf("Loi giai ma CBC (padding sai?).\n");
            return 1;
        }
    } else {
        pt_len = ctr_decrypt(key, iv,
                             ciphertext, ct_len,
                             decrypted);
        if (pt_len < 0) {
            printf("Loi giai ma CTR.\n");
            return 1;
        }
    }

    printf("\nPlaintext sau giai ma:\n");
    if (plaintext_is_ascii) {
        // đảm bảo kết thúc chuỗi
        if (pt_len < MAX_PLAINTEXT_LEN) {
            decrypted[pt_len] = '\0';
        } else {
            decrypted[MAX_PLAINTEXT_LEN] = '\0';
        }
        printf("  ASCII: %s\n", decrypted);
        print_hex("  HEX  : ", decrypted, pt_len);
    } else {
        print_hex("  HEX  : ", decrypted, pt_len);
    }

    printf("\nHoan tat.\n");
    return 0;
}
