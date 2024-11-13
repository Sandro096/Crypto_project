import argparse
import module

def main():

    # Main Parser
    parser = argparse.ArgumentParser(description="Cryptography Tool")

    # Creating sub-commands
    subparsers = parser.add_subparsers(dest="command", help="Choose a command:")

    generate_key_parser = subparsers.add_parser("generate_key", help="Generate a new encryption key")
    generate_key_parser.add_argument("key_name", type=str, help="Choose the name of the key")

    file_cript_parser = subparsers.add_parser("file_crypt", help="Encrypt an already existing file")
    file_cript_parser.add_argument("file_name", type=str, help="File name to encrypt")
    file_cript_parser.add_argument("key_file", type=str, help="Choose the key to be used for encryption")

    new_file_parser = subparsers.add_parser("crypt_new", help="Create and encrypt a new file")
    new_file_parser.add_argument("newfile_name", type=str, help="New file name")
    new_file_parser.add_argument("content", type=str, help="Write the content of the new file")
    new_file_parser.add_argument("key_file", type=str, help="Choose the key to be used for encryption")

    decrypt_file_parser = subparsers.add_parser("decrypt", help="Decrypt an already existing file")
    decrypt_file_parser.add_argument("file_name", type=str, help="File name to decrypt")
    decrypt_file_parser.add_argument("key_file", type=str, help="Choose the key to be used for decryption")

    file_crypt_with_password_parser = subparsers.add_parser("crypt_with_pass", help="Encrypt file with a password")
    file_crypt_with_password_parser.add_argument("file_name", type=str, help="Name of the file to encrypt")
    file_crypt_with_password_parser.add_argument("password", type=str, help="Choose the password to be used for encryption")

    decrypt_file_with_password_parser = subparsers.add_parser("decrypt_with_pass", help="Decrypt file with a password")
    decrypt_file_with_password_parser.add_argument("file_name", type=str, help="Name of the file to decrypt")
    decrypt_file_with_password_parser.add_argument("password", type=str, help="Choose the password to use for decryption")

    # Parse the command-line arguments
    args = parser.parse_args()

    # Command to generate a new encryption key and save it to the specified file
    if args.command == "generate_key":
        module.generate_key(args.key_name)

    # Command to encrypt an existing file using a previously generated key
    elif args.command == "file_crypt":
        # Load the encryption key from the specified file
        cipher_suite = module.load_key(args.key_file)
        if cipher_suite:
            # If the key is loaded successfully, encrypt the specified file
            module.crypt_file(args.file_name, cipher_suite)

    # Command to create a new file with content and encrypt it using a provided key
    elif args.command == "crypt_new":
        # Load the encryption key from the specified file
        cipher_suite = module.load_key(args.key_file)
        if cipher_suite:
            # If the key is loaded successfully, create the new file with content
            module.create_file(args.newfile_name, args.content)
            # Encrypt the newly created file
            module.crypt_file(args.newfile_name, cipher_suite)

    # Command to encrypt a file using a password (password-based encryption)
    elif args.command == "crypt_with_pass":
        # Encrypt the specified file using the provided password
        module.crypt_file_with_password(args.file_name, args.password)

    # Command to decrypt a file using a previously generated key
    elif args.command == "decrypt":
        # Load the encryption key from the specified file
        cipher_suite = module.load_key(args.key_file)
        if cipher_suite:
            # If the key is loaded successfully, decrypt the specified file
            module.decrypt_file(args.file_name, cipher_suite)

    # Command to decrypt a file using a password (password-based decryption)
    elif args.command == "decrypt_with_pass":
        # Decrypt the specified file using the provided password
        module.decrypt_file_with_password(args.file_name, args.password)

if __name__ == "__main__":
    main()