import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes) -> bytes:
    """
        Turns a master password + salt into a 32-byte (256-bit) AES key.
        - password: what the user types
        - salt: random bytes stored in the vault (not secret, but must be unique)
        - 600,000 iterations: makes brute-forcing take ~minutes per guess instead of microseconds
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                   # 32 bytes = 256 bits
        salt=salt,
        iterations=600_000,          # NIST recommended minimum as of 2023
    )
    return kdf.derive(password.encode())   # .encode() converts string -> bytes

def encrypt(key: bytes, plaintext: str) -> dict:
    """
        Encrypts a string using AES-256-GCM.
        Returns a dict with the nonce + ciphertext (both base64-encoded for JSON storage).
        - nonce: a random 12-byte number used ONCE per encryption. Never reuse a nonce!
        - GCM mode produces a 'tag' appended to ciphertext that detects any tampering
    """
    nonce = os.urandom(12)   # 12 bytes is the standard nonce size for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt(key: bytes, encrypted: dict) -> str:
    """
        Reverses encrypt(). Takes the same dict and returns the original string.
        Raises an exception if the key is wrong OR if the data was tampered with.
    """
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()