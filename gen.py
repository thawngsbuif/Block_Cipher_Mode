from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def choose_mode():
    print("Chọn chế độ AES:")
    print("1. ECB")
    print("2. CBC")
    print("3. CTR")
    print("4. OFB")
    choice = input("Nhập lựa chọn (1-4): ").strip()

    if choice == "1":
        return "ECB"
    elif choice == "2":
        return "CBC"
    elif choice == "3":
        return "CTR"
    elif choice == "4":
        return "OFB"
    else:
        print("Lựa chọn không hợp lệ, mặc định dùng CBC.")
        return "CBC"


def main():
    mode_name = choose_mode()

    # 128-bit key (AES-128)
    key = os.urandom(16)   # 16 bytes
    print(f"\n=== MODE: {mode_name} ===")
    print(f"Key (hex): {key.hex()}")

    # Plaintext (cố định để so sánh giữa các mode)
    plaintext = b"Secret Message!"  # 15 bytes
    print(f"Plaintext (ASCII): {plaintext.decode('utf-8')}")
    print(f"Plaintext (hex):   {plaintext.hex()}")

    backend = default_backend()

    # Tạo mode + IV/Nonce nếu cần
    iv = None
    if mode_name == "ECB":
        cipher_mode = modes.ECB()
    else:
        # CBC / CTR / OFB đều cần 16-byte IV/nonce
        iv = os.urandom(16)
        if mode_name == "CBC":
            cipher_mode = modes.CBC(iv)
        elif mode_name == "CTR":
            cipher_mode = modes.CTR(iv)
        elif mode_name == "OFB":
            cipher_mode = modes.OFB(iv)
        else:
            # fallback
            cipher_mode = modes.CBC(iv)

        print(f"IV / Nonce (hex): {iv.hex()}")

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=backend)
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Với ECB/CBC cần padding khối, CTR/OFB có thể xem như stream -> không cần padding
    if mode_name in ("ECB", "CBC"):
        print("\n-- Sử dụng PKCS#7 padding cho ECB/CBC --")
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        print(f"Ciphertext (bytes): {ciphertext}")
        print(f"Ciphertext (hex):   {ciphertext.hex()}")

        # Decrypt
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    else:
        # CTR/OFB: không padding
        print("\n-- Không dùng padding cho CTR/OFB --")
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        print(f"Ciphertext (bytes): {ciphertext}")
        print(f"Ciphertext (hex):   {ciphertext.hex()}")

        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"Decrypted (ASCII): {decrypted.decode('utf-8')}")
    print(f"Decrypted (hex):   {decrypted.hex()}")


if __name__ == "__main__":
    main()
