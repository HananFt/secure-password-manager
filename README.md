# 🔐 VaultX - Secure Password Manager

A modern, encrypted password vault with both GUI and CLI interfaces.
Passwords are protected with AES-256-GCM and the master password is
never stored — only a derived key via PBKDF2.

---

## Features

- 🔒 **Military-grade encryption** — AES-256-GCM with unique nonces per entry
- 🔑 **Strong key derivation** — PBKDF2 with 600,000 iterations (NIST recommended)
- 🛡️ **Tamper detection** — GCM authentication tags prevent undetected modification
- 🎨 **Modern GUI** — Dark-themed interface built with CustomTkinter
- 📋 **Clipboard integration** — One-click password copying
- 🔄 **Password re-encryption** — Seamless master password changes
- ⏱️ **Auto-lock** — Vault locks after user-defined inactivity
- 🔑 **Password generator** — Generate strong, random passwords
- 📊 **Password strength meter** — Real-time feedback on password quality
- 🔐 **Recovery codes** — 10 one-time use codes for account recovery
- 📦 **Zero-trust architecture** — Master password never stored or transmitted
- 🖥️ **CLI & GUI** — Same security model, two interfaces

---

## Security Model

```
Master Password + Unique Salt
│
▼
PBKDF2-SHA256
(600,000 iterations)
│
▼
256-bit AES Key ──► AES-256-GCM ──► vault.json
│
▼
Per-entry random nonce + Authentication tag
```

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/HananFt/secure-password-manager.git
cd secure-password-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install cryptography customtkinter pyperclip
```

### Usage

**GUI (Recommended)**
```bash
python app.py
```

**CLI (Terminal)**
```bash
python manager.py
```

### First-Time Setup

On first run, you'll be prompted to:

1. Create a master password (minimum 8 characters)
2. Receive 10 recovery codes — store them securely!
3. A `vault.json` file is created locally
4. Add your first password entry

---

## Project Structure

```
secure-password-manager/
├── app.py           # GUI application (CustomTkinter)
├── manager.py       # CLI interface
├── crypto.py        # Core encryption logic
├── vault.py         # Vault storage operations
├── requirements.txt
└── README.md
```

---

## Technical Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12+ |
| Encryption | AES-256-GCM, PBKDF2-HMAC-SHA256 |
| GUI | CustomTkinter |
| Platform | Cross-platform (Windows, macOS, Linux) |

---

## Feature Status

| Feature | Status | Location |
|---------|--------|----------|
| Auto-lock Timer | ✅ Implemented | Settings → Auto-lock Timer (configurable) |
| Password Generator | ✅ Implemented | Settings → Password Generator & Add Entry dialog |
| Password Strength Meter | ✅ Implemented | Login, Add Entry, Settings |
| Recovery Codes | ✅ Implemented | Created on vault creation, viewable in Settings |

---

## Security Notes

- The vault salt is stored in plaintext (non-secret by design)
- Each password entry uses a unique 12-byte random nonce
- GCM authentication prevents tampering — modified vaults fail decryption
- Master password is never written to disk or logged
- Clipboard contents are cleared after 30 seconds
- Recovery codes are encrypted with the master password

---

## License

MIT

---

## Author

**HananFt** — [GitHub](https://github.com/HananFt)