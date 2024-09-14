import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to expand a short key to 32 bytes
def expand_key(short_key):
    return (short_key * (32 // len(short_key) + 1))[:32]

# Function to encrypt data with AES-256
def aes256_encrypt(data, key):
    expanded_key = expand_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(expanded_key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data with AES-256
def aes256_decrypt(encrypted_data_hex, key):
    # Convert hex input to bytes
    encrypted_data = binascii.unhexlify(encrypted_data_hex)
    
    expanded_key = expand_key(key)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(expanded_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Example usage
short_key = b"1234"  # 2-byte key
data = b"0123456789"

# Encrypt the data
encrypted = aes256_encrypt(data, short_key)

# Convert encrypted data to hex
encrypted_hex = binascii.hexlify(encrypted).decode()
print("Encrypted (Hex):", encrypted_hex)

# Decrypt the data using the hex input

decrypted = aes256_decrypt(b"cb047d1c2acf1f28c849076b66e27b8abd9ee5392f2f0ab1115efb634bb65616", b"1234" )
print("Decrypted:", decrypted)
