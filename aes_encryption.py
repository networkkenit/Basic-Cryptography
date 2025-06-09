# aes_encryption.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[-1])]

def aes_encrypt(plaintext, key):
    key = key[:16].ljust(16, '0').encode()
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plaintext).encode())
    return b64encode(ct_bytes).decode()

def aes_decrypt(ciphertext, key):
    key = key[:16].ljust(16, '0').encode()
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(b64decode(ciphertext))
    return unpad(pt.decode())


if __name__ == "__main__":
    key = "mysecretkey12345"
    text = "Hello AES Encryption"
    encrypted = aes_encrypt(text, key)
    decrypted = aes_decrypt(encrypted, key)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
