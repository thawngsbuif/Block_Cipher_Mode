from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# 128 bit key (AES-128)
key = os.urandom(16)   # AES-128

print(f"Key (hex): {key.hex()}")
iv  = os.urandom(16)   # Initialization vector 

print(f"IV (hex): {iv.hex()}")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

# Plaintext
plaintext = b"Secret Message!"


print(f"Plaintext (ASCII): {plaintext.decode('utf-8')}")
print(f"Plaintext (hex):   {plaintext.hex()}")

# Padding
padder = padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()

# Encrypt
ciphertext = encryptor.update(padded_data) + encryptor.finalize()
print(f"Ciphertext (bytes): {ciphertext}")
print(f"Ciphertext (hex):   {ciphertext.hex()}")

# Decrypt
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

print(f"Decrypted (ASCII): {decrypted_data.decode('utf-8')}")
print(f"Decrypted (hex):   {decrypted_data.hex()}")
