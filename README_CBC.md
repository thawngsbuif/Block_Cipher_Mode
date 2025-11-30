# AES-128 CBC + PKCS#7 – Demo & Test

## Mục đích  
Mã hoá / giải mã dùng AES-128 theo mode CBC, với padding PKCS#7.  

## Cấu trúc file  
- `aes.h`, `aes.c` — thuật toán AES-128 (encrypt / decrypt 1 block 16 byte)  
- `cbc.h`, `cbc.c` — mode CBC + padding/unpadding  
- `main.c` — chương trình chính cho người dùng nhập key / IV / plaintext → mã hoá & giải mã  

## Biên dịch và chạy  
```bash
gcc -std=c11 -O2 main1.c aes.c cbc.c -o aes_cbc_demo
./aes_cbc_demo
```
## Test vector
1.Bộ 1: 
- KEY       = b27b76abc7e82bc71ed4459305a6c461
- IV        = 9579cb01a97a66e1f7553da99ea23f05
- PLAINTEXT = 536563726574204d65737361676521 (hex), or as ASCII:  Secret Message!
- CIPHERTEXT= 57459417562e6db125b670020ef631a5