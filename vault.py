import json
import os

VAULT_FILE = "vault.json"

def vault_exists() -> bool:
    """Check if a vault has been created yet."""
    return os.path.exists(VAULT_FILE)

def load_vault() -> dict:
    """Read and return the vault file as a Python dict."""
    with open(VAULT_FILE, "r") as f:
        return json.load(f)
    
def save_vault(data: dict):
    """Write a Python dict to the vault file as JSON."""
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def init_vault(salt_b64: str):
    """
        Create a brand new empty vault.
        The salt is generated in manager.py and passed in here.
        We store it in plaintext, that's fine and intentional.
        Salt isn't a secret, it just ensures two users with the same master password still get different encryption keys.
    """
    data = {
        "salt": salt_b64,
        "entries": {}
    }
    save_vault(data)