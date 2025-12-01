# AES-128 ECB + PKCS#7 – Demo & Test

## Mục đích  
Mã hoá / giải mã dùng AES-128 theo mode ECB, với padding PKCS#7.  

## Cấu trúc file  
- `aes.h`, `aes.c` — thuật toán AES-128 (encrypt / decrypt 1 block 16 byte)  
- `cbc.h`, `cbc.c` — mode EBC + padding/unpadding  
- `main.c` — chương trình chính cho người dùng nhập key / IV / plaintext → mã hoá & giải mã  

## Biên dịch và chạy  
```bash
gcc aes.c ecb.c main.c -o aes_ecb_test
./aes_ecb_test
```
## Test vector
1. Bộ 1:
- Key (hex): 08907f556b7244cc6b268d1c00a39995
- Plaintext (ASCII): Secret Message!
- Plaintext (hex):   536563726574204d65737361676521
- Ciphertext (hex):   e2c1d0c5f039f6fe5a6d55f1c70facd8
2. Bộ 2:
- Key (hex): b230d8643f75cfbac989b71bdb9845fd
- Plaintext (ASCII): Secret Message!
- Plaintext (hex):   536563726574204d65737361676521 
- Ciphertext (hex):   894a6ef7e5076e098b32cdbe89222d1a
3. Bộ 3:
- Key (hex): 4bf44e89c13cfef80b1dd96b07f9e7bd
- Plaintext (ASCII): Secret Message!
- Plaintext (hex):   536563726574204d65737361676521
- Ciphertext (hex):   fd9d8f0c909328c4192f8e02ebc14565
## Hướng dẫn tạo Test vector:
- Người dùng thực hiện file `gen_test_vector.py`, chỉ cần thay đổi nội dung plaintext sẽ tự động sinh ra test vector tương ứng.
