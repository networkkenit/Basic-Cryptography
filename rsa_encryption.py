# rsa_encryption.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    return public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

# Demo test
if __name__ == "__main__":
    private_key, public_key = generate_keys()
    msg = "Hello RSA!"
    encrypted = rsa_encrypt(msg, public_key)
    decrypted = rsa_decrypt(encrypted, private_key)

    print("Encrypted:", encrypted.hex())
    print("Decrypted:", decrypted)
