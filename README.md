# Cryptography Tool
This project provides a command-line cryptography tool for managing encryption and decryption tasks on files.  
Using Python's argparse module, the tool supports multiple commands for handling various encryption scenarios, leveraging the cryptography library for secure operations. 

The available commands and their functionalities include:  

**generate_key**: Generates a new Fernet encryption key and saves it to a specified file.  
**file_crypt**: Encrypts an existing file using a specified key.  
**crypt_new**: Creates a new file with user-specified content and encrypts it using a key.  
**decrypt**: Decrypts an encrypted file using a specified key.  
**crypt_with_pass**: Encrypts a file with a password-derived key, using PBKDF2 for secure key derivation.  
**decrypt_with_pass**: Decrypts a file encrypted with a password-derived key.


**Key Features**:  
**Argparse Subcommands**: Each operation has its own command, making it easy to manage multiple cryptographic tasks from the command line.  
**Password-based Encryption**: Uses PBKDF2 with a random salt to derive encryption keys securely from passwords.  
**Error Handling**: Includes error messages for cases like missing keys, incorrect passwords, and pre-encrypted files.  
