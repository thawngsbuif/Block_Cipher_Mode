from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def to_hex(b: bytes) -> str:
    return b.hex()


def print_c_array(name: str, b: bytes):
    print(f"{name}[{len(b)}] = {{", end="")
    for i, byte in enumerate(b):
        sep = ", " if i != len(b) - 1 else ""
        print(f"0x{byte:02X}{sep}", end="")
    print("};")


def gen_cbc_vector(key: bytes, iv: bytes, plaintext: bytes):
    print("=== AES-128-CBC + PKCS#7 ===")
    print(f"Key (hex): {to_hex(key)}")
    print(f"IV  (hex): {to_hex(iv)}")
    print(f"Plaintext (ASCII): {plaintext.decode('utf-8', errors='ignore')}")
    print(f"Plaintext (hex):   {to_hex(plaintext)}")

    # Padding PKCS7 (block size 128 bit = 16 byte)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    print(f"Ciphertext (bytes): {ciphertext}")
    print(f"Ciphertext (hex):   {to_hex(ciphertext)}")

    # Decrypt để verify
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    print(f"Decrypted (ASCII): {decrypted_data.decode('utf-8', errors='ignore')}")
    print(f"Decrypted (hex):   {to_hex(decrypted_data)}")

    print("\n// ==== C ARRAYS (CBC) ====")
    print_c_array("unsigned char key", key)
    print_c_array("unsigned char iv", iv)
    print_c_array("unsigned char plaintext", plaintext)
    print_c_array("unsigned char ciphertext_cbc", ciphertext)
    print()


def gen_ctr_vector(key: bytes, iv: bytes, plaintext: bytes):
    print("=== AES-128-CTR ===")
    print(f"Key (hex): {to_hex(key)}")
    print(f"IV  (hex): {to_hex(iv)}  # dung lam counter block 16 byte")
    print(f"Plaintext (ASCII): {plaintext.decode('utf-8', errors='ignore')}")
    print(f"Plaintext (hex):   {to_hex(plaintext)}")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    print(f"Ciphertext (bytes): {ciphertext}")
    print(f"Ciphertext (hex):   {to_hex(ciphertext)}")

    # Decrypt verify
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"Decrypted (ASCII): {decrypted_data.decode('utf-8', errors='ignore')}")
    print(f"Decrypted (hex):   {to_hex(decrypted_data)}")

    print("\n// ==== C ARRAYS (CTR) ====")
    print_c_array("unsigned char key", key)
    print_c_array("unsigned char iv", iv)
    print_c_array("unsigned char plaintext", plaintext)
    print_c_array("unsigned char ciphertext_ctr", ciphertext)
    print()


def main():
    # Giống file gốc: key & iv random 16 byte
    key = os.urandom(16)   # AES-128
    iv  = os.urandom(16)   # IV / counter block

    plaintext = b"Secret Message!"  # hoặc sửa cái khác nếu bạn muốn

    gen_cbc_vector(key, iv, plaintext)
    print("\n" + "=" * 60 + "\n")
    gen_ctr_vector(key, iv, plaintext)


if __name__ == "__main__":
    main()
