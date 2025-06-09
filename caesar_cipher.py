# caesar_cipher.py

def caesar_encrypt(plaintext, shift):
    result = ''
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)



if __name__ == "__main__":
    text = "Hello, World!"
    shift = 3
    encrypted = caesar_encrypt(text, shift)
    decrypted = caesar_decrypt(encrypted, shift)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
