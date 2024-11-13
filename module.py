from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Function to generate a new encryption key
def generate_key(file_name):
    key = Fernet.generate_key() # Generate a secret key using Fernet
    # Save the key to the specified file in binary format
    with open(file_name, "wb") as key_file:
        key_file.write(key)
    print(f"Key generated and saved as '{file_name}'.")

# Function to load an encryption key from a file
def load_key(file_name):
    if os.path.exists(file_name): # Check if the key file exists
        with open(file_name, "rb") as key_file:
            return Fernet(key_file.read())  # Load and return the key

    else:
        # Error message if the key does not exist
        print(f"Error: file '{file_name}' containing the key does not exist.")
        return

# Function to create a new file with a specified content
def create_file(file_name, content):
    with open(file_name, "w") as file:
        file.write(content)  # Write the content to the file
    print(f"File '{file_name}' successfully created.")

# Function to encrypt an existing file using an encryption key
def crypt_file(file_name, cipher_suite):
    # Check if the file does not exist, and generate an error message
    if not os.path.exists(file_name):  
        print(f"Error: file '{file_name}' does not exist.")
        return
    
    # Check if the file is already encrypted with a specific key
    # Files can be encrypted different times, just with different keys
    if is_encrypted(file_name, cipher_suite):
        print("Error: the file is already encrypted with the chosen key.")
        return
    
    else:
    # Open the file and read its content in binary format
        with open(file_name, "rb") as file:
            binary_file = file.read()
            # Encrypt the content using the cipher suite
            crypt_file = cipher_suite.encrypt(binary_file)
        # Write the encrypted content back to the file
        with open(file_name, "wb") as enc_file:
            enc_file.write(crypt_file)
            print(f"File '{file_name}' successfully encrypted.")

# Function to decrypt a file using an encryption key.
# To decrypt a file encrypted with multiple keys, 
# you need to follow the encryption path in reverse order:
# (file encrypt secret.key1 - secret.key2 ---> file decrypt secret.key2 - secret.key1).
def decrypt_file(file_name, cipher_suite):
    # Try to read, decrypt and overwrite the file
    try:
        # Read the encrypted content
        with open(file_name, "rb") as crypt_file:
            content = crypt_file.read()
        
        # Decrypt the content
        plain_text = cipher_suite.decrypt(content)
        
        # Overwrite the original file with the decrypted content
        with open(file_name, "wb") as file:
            file.write(plain_text)
        
        print(f"File '{file_name}' successfully decrypted.")
    except InvalidToken:
        # Error message if the user tries to decrypt the file with the wrong key or the file is already in plain text
        if is_encrypted(file_name, cipher_suite) == False:
            print("Error: incorrect key or file already in plain text.")

def is_encrypted(file_name, cipher_suite):
    try:
        # Try to read the file
        with open(file_name, "rb") as file:
            content = file.read()
        # Try to decrypt the content of the file
        cipher_suite.decrypt(content)
        return True  # If no exception is raised, the file was already encrypted with this cipher suite
    except Exception:
        return False # If an exception is raised, the file was not encrypted with this cipher suite
        
# Function to generate a cryptographic key from a password using PBKDF2
def generate_key_from_password(password: str) -> bytes:
    salt = os.urandom(16)   # Generate a random salt to ensure uniqueness of the derived key
                            # even if the same password is used again. The salt adds randomness
    # Create a Key Derivation Function (KDF) using PBKDF2 with SHA-256 hash algorithm
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # Hash function used in key derivation
        length=32,  # Desired key length in bytes (32 bytes for Fernet compatibility)
        salt=salt,  # Unique salt value for this key
        iterations=100000,  # Number of iterations
        backend=default_backend() # Cryptographic backend for hashing operations
    )
    # Derive a 32-byte key from the password using the defined KDF
    key = kdf.derive(password.encode())
    # Return both the derived key and the salt, as the salt is needed for decryption
    return key, salt

# Function to encrypt a file using a password
# Files can be encrypted several times with the same password
def crypt_file_with_password(file_name, password):
    # Generate a random salt for key derivation
    salt = os.urandom(16)
    
    # Initialize a KDF to derive a cryptographic key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    # Derive a cryptographic key from the password
    key = kdf.derive(password.encode())
    
    # Convert the derived key to a base64 URL-safe format, required by Fernet for encryption
    base64_key = base64.urlsafe_b64encode(key)
    
    # Initialize Fernet encryption with the encoded key
    cipher_suite = Fernet(base64_key)

    # Read the contents of the file to encrypt
    with open(file_name, "rb") as file:
        binary_file = file.read()
    
    # Encrypt the file contents
    encrypted_file = cipher_suite.encrypt(binary_file)
    
    # Overwrite the original file with the salt and the encrypted content
    with open(file_name, "wb") as enc_file:
        enc_file.write(salt + encrypted_file) # Add the salt at the beginning of the encrypted data for use during decryption
    
    print(f"File '{file_name}' successfully encrypted")

# Function to decrypt a file using a password
def decrypt_file_with_password(file_name, password):
    
    # Read the encrypted file contents
    with open(file_name, "rb") as crypt_file:
        encrypted_content = crypt_file.read()
    
    # Extract the salt from the first 16 bytes of the file
    salt = encrypted_content[:16]
    encrypted_content = encrypted_content[16:] # Remaining data is the encrypted content

    # Use the extracted salt to derive the same key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    # Derive the key from the password
    key = kdf.derive(password.encode())

    # Encode the derived key in base64 for Fernet compatibility
    base64_key = base64.urlsafe_b64encode(key)
    
    # Initialize Fernet with the derived and encoded key
    cipher_suite = Fernet(base64_key)
    
    # Attempt to decrypt the file content
    try:
        decrypted_content = cipher_suite.decrypt(encrypted_content)
 
        # Overwrite the file with the decrypted content
        with open(file_name, "wb") as file:
            file.write(decrypted_content)
    
        print(f"File '{file_name}' successfully decrypted!")
    except InvalidToken:
        # If decryption fails, it is likely due to incorrect password
        print("Error: wrong password.")