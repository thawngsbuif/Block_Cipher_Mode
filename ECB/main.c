#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ecb.h"

int hex_to_bytes(const char *hex, uint8_t *out, int out_len) {
    int len = (int)strlen(hex);
    if (len != out_len * 2) return 0;
    for (int i = 0; i < out_len; i++) {
        char c1 = hex[2*i], c2 = hex[2*i+1];
        int hi = (c1 >= '0' && c1 <= '9') ? c1-'0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1-'a'+10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1-'A'+10 : -1;
        int lo = (c2 >= '0' && c2 <= '9') ? c2-'0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2-'a'+10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2-'A'+10 : -1;
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int main() {
    const int block_size = 16;
    uint8_t pt[256], key[16], ct[256], dec[256];
    char key_hex[64];

    printf("Plaintext: ");
    if (!fgets((char*)pt, sizeof(pt), stdin)) return 1;
    pt[strcspn((char*)pt, "\n")] = 0;
    int pt_len = (int)strlen((char*)pt);

    while (1) {
        printf("Key hex (32 ky tu): ");
        if (!fgets(key_hex, sizeof(key_hex), stdin)) return 1;
        key_hex[strcspn(key_hex, "\n")] = 0;
        if (hex_to_bytes(key_hex, key, 16)) break;
        puts("Key hex sai, nhap lai!");
    }

    int ct_len = 0, dec_len = 0;

    if (!encrypt_ecb(key, pt, pt_len, ct, block_size, &ct_len)) {
        puts("Encrypt error"); return 1;
    }

    printf("Ciphertext hex: ");
    for (int i = 0; i < ct_len; i++) printf("%02X", ct[i]);
    puts("");

    if (!decrypt_ecb(key, ct, ct_len, dec, block_size, &dec_len)) {
        puts("Decrypt error"); return 1;
    }
    dec[dec_len] = 0;
    printf("Decrypted: %s\n", dec);
    return 0;
}
