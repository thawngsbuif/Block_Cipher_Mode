# AES-128 CTR – Demo & Test

## Mục đích  
Mã hoá / giải mã dùng AES-128 theo mode CTR.  

## Cấu trúc file  
- aes.h, aes.c — thuật toán AES-128 (encrypt / decrypt 1 block 16 byte)  
- cbc.h, cbc.c — mode CTR  
- main.c — chương trình chính cho người dùng nhập key / IV / plaintext → mã hoá & giải mã  

## Biên dịch và chạy  
gcc main1.c aes.c ctr.c -o ctr_test.exe
.\ctr_test.exe
## Test vector
1. Bộ 1: 
- Key (hex): b301d6d67c9a562cd97febc121092c6c
- IV  (hex): 2c3b31f926713463183b247b57003b8a  # dung lam counter block 16 byte
- Plaintext (ASCII): Secret Message!
- Plaintext (hex):   536563726574204d65737361676521
- Ciphertext (hex):   a57a8e9a2bbdf03598bec8b878104f

2. Bộ 2:
- Key (hex): 8a8b611bf97c1959e553033f0bf6846b
- IV  (hex): e36c80307eb4f53d7377f2034314d497  # dung lam counter block 16 byte
- Plaintext (ASCII): Secret Message!
- Plaintext (hex):   536563726574204d65737361676521
- Ciphertext (hex):   8b64be6125c18e81b48e11e94c54ff

## Hướng dẫn tạo Test vector:
- Người dùng thực hiện file gen_test_vector.py, chỉ cần thay đổi nội dung plaintext sẽ tự động sinh ra test vector tương ứng.
