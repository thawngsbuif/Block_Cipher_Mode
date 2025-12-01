from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ===============================
#  AES-128 OFB TEST VECTOR
# ===============================
# Để dễ test với code C, mình dùng KEY & IV cố định.
# Nếu muốn random thì có ghi chú phía dưới.

# 16 byte = 128 bit
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

print(f"Key (hex): {key.hex()}")
print(f"IV  (hex): {iv.hex()}")

# Plaintext mẫu (bạn sửa thoải mái)
plaintext = b"Hello AES-128 OFB mode!"

print(f"Plaintext (ASCII): {plaintext.decode('utf-8')}")
print(f"Plaintext (hex)  : {plaintext.hex()}")

# ===============================
#  PKCS#7 padding (block size 128 bit)
# ===============================
padder = padding.PKCS7(128).padder()
padded = padder.update(plaintext) + padder.finalize()

# ===============================
#  ENCRYPT - AES-128 OFB
# ===============================
backend = default_backend()
cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()

print(f"Ciphertext (bytes): {ciphertext}")
print(f"Ciphertext (hex)  : {ciphertext.hex()}")

# ===============================
#  DECRYPT - kiểm tra lại
# ===============================
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

print(f"Decrypted (ASCII): {decrypted.decode('utf-8')}")
print(f"Decrypted (hex)  : {decrypted.hex()}")

# ===============================
#  GHI CHÚ:
#  - Dùng key/iv/plaintext/ciphertext bên trên để test
#    với chương trình C (ofb_encrypt_pkcs7 / ofb_decrypt_pkcs7).
#  - Nếu muốn random key/iv giống bản trước, thay 2 dòng key/iv bằng:
#
#    import os
#    key = os.urandom(16)
#    iv  = os.urandom(16)
# ===============================
