# SecureVault

SecureVault is a Python program designed to securely encrypt and decrypt files and folders using advanced cryptographic techniques. It allows users to protect their sensitive information with a password and manage encrypted folders efficiently.

## Features

- **Folder Encryption:** Encrypts all files within a specified folder.
- **Folder Decryption:** Decrypts all files within a specified encrypted folder.
- **Password Management:** Securely stores and verifies user passwords.
- **Metadata Management:** Maintains a list of encrypted folders to prevent duplication.

## Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - `cryptography`
  - `bcrypt`
  - `colorama`
  
You can install the required packages using pip:

```bash
pip install cryptography bcrypt colorama
