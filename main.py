import os
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import secrets
import getpass
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Paths to store metadata
METADATA_FILE = 'encryption_metadata.json'
PASSWORD_FILE = 'password.hash'

# Utility functions to handle key derivation and encryption
def generate_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash)

# File encryption and decryption
def encrypt_file(file_path, key):
    iv = secrets.token_bytes(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    padder = padding.PKCS7(128).padder()

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + ".enc", 'wb') as f:
        f.write(iv + encrypted_data)

    os.remove(file_path)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path[:-4], 'wb') as f:
        f.write(data)

    os.remove(file_path)

# Folder encryption
def encrypt_folder(folder_path, password):
    try:
        folder_path = os.path.abspath(os.path.normpath(folder_path))  # Normalize Windows-style paths
        salt = secrets.token_bytes(16)
        key = generate_key(password, salt)

        # Save the salt to the folder
        with open(os.path.join(folder_path, 'salt.bin'), 'wb') as f:
            f.write(salt)

        # Encrypt each file in place
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith('.enc') and file != 'salt.bin':
                    encrypt_file(file_path, key)
                    print(Fore.GREEN + f"Encrypted: {file_path}")

        print(Fore.CYAN + f"All files in '{folder_path}' have been encrypted.")
        store_encrypted_folder(folder_path)
    except Exception as e:
        print(Fore.RED + f"Error during encryption: {e}. Returning to main menu.")

# Folder decryption
def decrypt_folder(folder_path, password):
    try:
        folder_path = os.path.abspath(os.path.normpath(folder_path))  # Normalize Windows-style paths
        encrypted_folder = folder_path

        with open(os.path.join(encrypted_folder, 'salt.bin'), 'rb') as f:
            salt = f.read()

        key = generate_key(password, salt)

        for root, dirs, files in os.walk(encrypted_folder):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.enc'):
                    decrypt_file(file_path, key)
                    print(Fore.GREEN + f"Decrypted: {file_path}")

        print(Fore.CYAN + f"All files in '{encrypted_folder}' have been decrypted.")
    except Exception as e:
        print(Fore.RED + f"Error during decryption: {e}. Returning to main menu.")

# Metadata storage for encrypted folders
def store_encrypted_folder(folder_url):
    data = load_metadata()

    # Avoid storing duplicate folder URLs
    if folder_url not in data['encrypted_folders']:
        data['encrypted_folders'].append(folder_url)
        save_metadata(data)
        print(Fore.GREEN + f"Folder '{folder_url}' added to encrypted folder list.")
    else:
        print(Fore.YELLOW + f"Folder '{folder_url}' is already in the encrypted folder list.")

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {"encrypted_folders": []}
    with open(METADATA_FILE, 'r') as f:
        return json.load(f)

def save_metadata(data):
    with open(METADATA_FILE, 'w') as f:
        json.dump(data, f)

# Password handling
def initialize_password():
    if os.path.exists(PASSWORD_FILE):
        return

    password = getpass.getpass("Set a password for the first time: ")
    hashed_password = hash_password(password)

    with open(PASSWORD_FILE, 'wb') as f:
        f.write(hashed_password)

def verify_existing_password():
    try:
        with open(PASSWORD_FILE, 'rb') as f:
            stored_hash = f.read()

        password = getpass.getpass("Enter your password: ")
        if not verify_password(stored_hash, password):
            print(Fore.RED + "Incorrect password!")
            return None
        return password
    except Exception as e:
        print(Fore.RED + f"Error verifying password: {e}. Returning to main menu.")
        return None

def change_password():
    try:
        old_password = verify_existing_password()
        if not old_password:
            return

        new_password = getpass.getpass("Enter a new password: ")
        hashed_password = hash_password(new_password)

        with open(PASSWORD_FILE, 'wb') as f:
            f.write(hashed_password)

        print(Fore.GREEN + "Password successfully changed.")
    except Exception as e:
        print(Fore.RED + f"Error changing password: {e}. Returning to main menu.")



def print_banner():
    print(Fore.CYAN + Style.BRIGHT)
    print("*******************************************************")
    print("*                                                     *")
    print("*    ███████╗██╗  ██╗██╗  ██╗██╗   ██╗ █████╗       *")
    print("*    ██╔════╝██║  ██║██║  ██║██║   ██║██╔══██╗      *")
    print("*    ███████╗███████║███████║██║   ██║███████║      *")
    print("*    ╚════██║██╔══██║██╔══██║██║   ██║██╔══██║      *")
    print("*    ███████║██║  ██║██║  ██║╚██████╔╝██║  ██║      *")
    print("*    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝      *")
    print("*                                                     *")
    print("*                  SecureVault                        *")
    print("*           Your fortress for encrypted files.       *")
    print("*                                                     *")
    print("*******************************************************")
    print(Style.RESET_ALL)

        
# Main program
def main():
    print_banner()
    initialize_password()

    while True:
        try:
            print(Style.BRIGHT + Fore.CYAN + "\n1. Encrypt a folder")
            print(Fore.CYAN + "2. Decrypt a folder")
            print(Fore.CYAN + "3. Change password")
            print(Fore.CYAN + "4. Exit")
            choice = input(Fore.YELLOW + "Select an option: ")

            if choice == '1':
                password = verify_existing_password()
                if password:
                    folder_path = input(Fore.YELLOW + "Enter the folder URL to encrypt: ")
                    encrypt_folder(folder_path, password)
            
            elif choice == '2':
                password = verify_existing_password()
                if password:
                    data = load_metadata()
                    if not data['encrypted_folders']:
                        print(Fore.RED + "No encrypted folders available.")
                    else:
                        print(Fore.CYAN + "Available encrypted folders:")
                        for idx, folder in enumerate(data['encrypted_folders']):
                            print(f"{idx + 1}. {folder}")
                        selection = int(input(Fore.YELLOW + "Select a folder to decrypt: ")) - 1
                        folder_path = data['encrypted_folders'][selection]
                        decrypt_folder(folder_path, password)
            
            elif choice == '3':
                change_password()

            elif choice == '4':
                print(Fore.GREEN + "Exiting.")
                break
            
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}. Returning to main menu.")

# Run the program
if __name__ == '__main__':
    main()
