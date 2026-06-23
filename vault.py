import json
import os

VAULT_FILE = "vault.json"

def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE)

def load_vault() -> dict:
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault(data: dict):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def init_vault(salt_b64: str, wrapped_vault_key: dict):
    """
    Create a brand new empty vault.
    - salt: used for PBKDF2 to derive the master key from the master password
    - wrapped_vault_key: the vault key encrypted under the master key
      The vault key is what actually encrypts entries, so changing the master
      password only requires re-wrapping this key, not re-encrypting all entries.
    """
    data = {
        "salt": salt_b64,
        "vault_key": wrapped_vault_key,
        "entries": {},
        "recovery_codes": []
    }
    save_vault(data)