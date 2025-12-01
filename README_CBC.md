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
1. Bộ 1: 
- KEY       = b27b76abc7e82bc71ed4459305a6c461
- IV        = 9579cb01a97a66e1f7553da99ea23f05
- PLAINTEXT = 536563726574204d65737361676521 (hex), or as ASCII:  Secret Message!
- CIPHERTEXT= 57459417562e6db125b670020ef631a5

2. Bộ 2:
- KEY       = 512a29b92c57e72b47a5a19f305dacec
- IV        = ef3098eed0df5d37a56da242cb81cecc
- PLAINTEXT = 5468656f7279206f662043727970746f677261706879 (hex), or as ASCII:  Theory of Cryptography
- CIPHERTEXT= ec9920dc403e66c51288b6d7b0c9080d080b039cc04563a70a0acffb97edf67d