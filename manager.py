import os
import base64
import getpass
from crypto import derive_key, generate_vault_key, wrap_key, unwrap_key, encrypt, decrypt
from vault import vault_exists, load_vault, save_vault, init_vault

def unlock() -> tuple[bytes, dict]:
    """
    Either initializes a new vault or unlocks an existing one.
    Returns (vault_key, vault_data). The vault_key encrypts entries directly;
    it is itself stored encrypted under the master password's derived key.
    """
    if not vault_exists():
        print("No vault found. Creating a new one.\n")
        master = getpass.getpass("Set your master password: ")
        confirm = getpass.getpass("Confirm master password: ")
        if master != confirm:
            print("Passwords don't match. Exiting.")
            exit()
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode()
        master_key = derive_key(master, salt)
        vault_key = generate_vault_key()
        wrapped = wrap_key(master_key, vault_key)
        init_vault(salt_b64, wrapped)
        print("\n✅ Vault created successfully!\n")
        return vault_key, load_vault()
    else:
        master = getpass.getpass("Master password: ")
        vault = load_vault()
        salt = base64.b64decode(vault["salt"])
        master_key = derive_key(master, salt)
        try:
            vault_key = unwrap_key(master_key, vault["vault_key"])
        except Exception:
            print("❌ Wrong password.")
            exit()
        return vault_key, vault

def add_entry(key: bytes, vault: dict):
    service = input("Service name (ex: gmail, github): ").strip()
    username = input("Username/email: ").strip()
    password = getpass.getpass("Password: ")
    vault["entries"][service] = {
        "username": username,
        "password": encrypt(key, password)
    }
    save_vault(vault)
    print(f"\n✅ Entry for '{service}' saved.\n")

def get_entry(key: bytes, vault: dict):
    service = input("Service name to retrieve: ").strip()
    if service not in vault["entries"]:
        print(f"\n❌ No entry found for '{service}'.\n")
        return
    entry = vault["entries"][service]
    try:
        password = decrypt(key, entry["password"])
        print(f"\n  Service : {service}")
        print(f"  Username : {entry['username']}")
        print(f"  Password : {password}\n")
    except Exception:
        print("\n❌ Decryption failed. Corrupted data.\n")

def list_entries(vault: dict):
    entries = vault["entries"]
    if not entries:
        print("\n Vault is empty.\n")
        return
    print("\n Stored services:")
    for service in entries:
        print(f"   - {service}  ({entries[service]['username']})")
    print()

def delete_entry(vault: dict):
    service = input("Service name to delete: ").strip()
    if service not in vault["entries"]:
        print(f"\n❌ No entry for '{service}'.\n")
        return
    del vault["entries"][service]
    save_vault(vault)
    print(f"\n✅ Entry for '{service}' deleted.\n")

def main():
    print("=" * 45)
    print("       🔐 Secure Password Manager")
    print("=" * 45 + "\n")
    key, vault = unlock()
    while True:
        print("What do you want to do?")
        print("  [1] Add a password")
        print("  [2] Get a password")
        print("  [3] List all services")
        print("  [4] Delete an entry")
        print("  [5] Quit")
        choice = input("\n> ").strip()
        if choice == "1": add_entry(key, vault)
        elif choice == "2": get_entry(key, vault)
        elif choice == "3": list_entries(vault)
        elif choice == "4": delete_entry(vault); vault = load_vault()
        elif choice == "5": print("Bye! :D"); break
        else: print("Invalid choice.\n")

if __name__ == "__main__":
    main()