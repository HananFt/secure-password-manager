# 🔐 Secure Password Manager

A command-line password vault built in Python. Passwords are encrypted with
AES-256-GCM and the master password is never stored — only a derived key via PBKDF2.

## Features

- AES-256-GCM encryption for all stored passwords
- PBKDF2 key derivation (600,000 iterations) — brute-force resistant
- Random salt per vault + random nonce per entry
- Master password never stored anywhere
- Tamper detection via GCM authentication tag
- Clean CLI interface with secure password input

## How It Works
Master Password + Salt

│
▼

PBKDF2-SHA256 (600k iterations)

│
▼

256-bit AES Key  ──►  AES-256-GCM  ──►  vault.json

## Setup

```bash
# Clone the repo
git clone https://github.com/HananFt/secure-password-manager.git
cd secure-password-manager

# Create virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # macOS/Linux

# Install dependency
pip install cryptography
```

## Usage

```bash
python manager.py
```

On first run, you'll set a master password and a vault is created locally.

| Option | Action |
|--------|--------|
| 1 | Add a password entry |
| 2 | Retrieve & decrypt a password |
| 3 | List all saved services |
| 4 | Delete an entry |
| 5 | Quit |

## Security Notes

- `vault.json` is **never committed** to this repo (see `.gitignore`)
- Each password entry uses a **unique random nonce** — no two encryptions are alike
- The salt ensures two users with the same master password get different keys

## Tech Stack

- Python 3.12+
- [`cryptography`](https://cryptography.io) library
- AES-256-GCM, PBKDF2-HMAC-SHA256

## License

MIT