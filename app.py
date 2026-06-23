import customtkinter as ctk
from tkinter import messagebox
import pyperclip
import os
import base64
import json
import secrets
import string
import time
from datetime import datetime
from crypto import derive_key, generate_vault_key, wrap_key, unwrap_key, encrypt, decrypt

# Check if vault exists and create if needed
VAULT_FILE = "vault.json"

def vault_exists():
    return os.path.exists(VAULT_FILE)

def load_vault():
    with open(VAULT_FILE, 'r') as f:
        return json.load(f)

def save_vault(vault):
    with open(VAULT_FILE, 'w') as f:
        json.dump(vault, f, indent=2)

def init_vault(salt_b64, wrapped_vault_key):
    vault = {
        "salt": salt_b64,
        "vault_key": wrapped_vault_key,   # vault key wrapped under master key
        "entries": {},
        "recovery_codes": [],
        "created_at": datetime.now().isoformat()
    }
    save_vault(vault)
    return vault

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# --- Palette ---
BG       = "#0d0d0d"
SURFACE  = "#141414"
CARD     = "#1a1a1a"
RED      = "#e05252"
RED_DIM  = "#2b1111"
RED_HOV  = "#c44040"
TEXT     = "#f2f2f2"
MUTED    = "#5a5a5a"
BORDER   = "#252525"
SUCCESS  = "#52b788"
YELLOW   = "#e5b83c"

FONT = "Segoe UI"

# --- Password Strength Meter ---

def check_password_strength(password: str) -> tuple[str, int, str]:
    """
    Returns (label, score, color)
    Score: 0-4 (Weak to Excellent)
    """
    if not password:
        return ("", 0, MUTED)
    
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/`~" for c in password):
        score += 1
    
    # Normalize to 0-4
    score = min(4, max(0, score - 1))
    
    labels = ["Weak", "Fair", "Good", "Strong", "Excellent"]
    colors = ["#e05252", "#e5b83c", "#52b788", "#4a9eff", "#7b61ff"]
    
    return labels[score], score, colors[score]

def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/`~"
    
    # Ensure at least one of each type for better distribution
    if use_symbols:
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?/`~")
        ]
    else:
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits)
        ]
    
    # Fill the rest
    password.extend(secrets.choice(chars) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# --- Password Entry with Toggle ---

class PasswordEntry(ctk.CTkFrame):
    def __init__(self, parent, placeholder="", var=None, show_strength=False, **kwargs):
        super().__init__(parent, fg_color="transparent")
        
        self.var = var if var else ctk.StringVar()
        self.show_password = False
        self.show_strength = show_strength
        
        # Main entry
        self.entry = ctk.CTkEntry(self, height=45, placeholder_text=placeholder, textvariable=self.var, show="●", fg_color=CARD, 
                                  border_color=BORDER, border_width=2, corner_radius=10, text_color=TEXT, placeholder_text_color=MUTED, 
                                  font=(FONT, 14), **kwargs)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        
        # Generate button (optional)
        self.gen_btn = None
        
        # Toggle button
        self.toggle_btn = ctk.CTkButton(self, text="👁", width=40, height=40, fg_color="transparent", hover_color=RED_DIM, 
                                        text_color=MUTED, corner_radius=8, font=(FONT, 16), command=self._toggle_password)
        self.toggle_btn.pack(side="right")
        
        # Strength meter (if enabled)
        self.strength_label = None
        self.strength_bar = None
        if show_strength:
            self.var.trace("w", lambda *a: self._update_strength())
    
    def add_generate_button(self):
        """Add a generate password button next to the entry."""
        self.gen_btn = ctk.CTkButton(self, text="🔑", width=40, height=40, fg_color="transparent", 
                                     hover_color=RED_DIM, text_color=MUTED, corner_radius=8, 
                                     font=(FONT, 16), command=self._generate_password)
        self.gen_btn.pack(side="right", padx=(0, 4))
    
    def _generate_password(self):
        """Generate a strong password and set it."""
        password = generate_password(20, True)
        self.var.set(password)
        self._update_strength()
    
    def _toggle_password(self):
        self.show_password = not self.show_password
        if self.show_password:
            self.entry.configure(show="")
            self.toggle_btn.configure(text="👁‍🗨")
        else:
            self.entry.configure(show="●")
            self.toggle_btn.configure(text="👁")
    
    def _update_strength(self):
        """Update the strength meter display."""
        if not self.show_strength:
            return
        
        password = self.var.get()
        label, score, color = check_password_strength(password)
        
        # Remove old strength widgets
        if self.strength_label:
            self.strength_label.destroy()
        if self.strength_bar:
            self.strength_bar.destroy()
        
        if password:
            # Create strength bar
            self.strength_bar = ctk.CTkFrame(self, height=3, fg_color=BORDER, corner_radius=2)
            self.strength_bar.pack(fill="x", pady=(4, 0))
            
            # Fill bar based on score
            fill = ctk.CTkFrame(self.strength_bar, height=3, fg_color=color, corner_radius=2, width=0)
            fill.pack(side="left", fill="x")
            # Update width after packing
            fill.configure(width=(score + 1) * 50)  # 50-250px
            
            # Label
            self.strength_label = ctk.CTkLabel(self, text=f"Strength: {label}", font=(FONT, 10), 
                                               text_color=color, height=16)
            self.strength_label.pack(anchor="w", pady=(2, 0))
    
    def get(self):
        return self.var.get()
    
    def set(self, value):
        self.var.set(value)
        self._update_strength()
    
    def bind(self, event, callback):
        self.entry.bind(event, callback)
    
    def focus(self):
        self.entry.focus()


# --- Login ---

class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_success):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self.on_success = on_success
        self._build()

    def _build(self):
        self.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Main container
        col = ctk.CTkFrame(self, fg_color="transparent", width=400)
        col.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo
        ctk.CTkLabel(col, text="🔐", font=(FONT, 48), text_color=RED).pack(pady=(0, 8))
        
        ctk.CTkLabel(col, text="VaultX", font=(FONT, 28, "bold"), text_color=TEXT).pack(pady=(0, 4))
        
        # Show status message
        if vault_exists():
            status = "✅ Vault found - Enter your master password"
        else:
            status = "🆕 No vault found - Create a new one"
            
        ctk.CTkLabel(col, text=status, font=(FONT, 13), text_color=SUCCESS if not vault_exists() else MUTED).pack(pady=(0, 30))

        # Master Password
        ctk.CTkLabel(col, text="Master Password", font=(FONT, 13, "bold"), text_color=TEXT).pack(anchor="w", pady=(0, 6))
        
        self.pw_var = ctk.StringVar()
        self.pw_entry = PasswordEntry(col, "Enter your master password", var=self.pw_var)
        self.pw_entry.pack(fill="x", pady=(0, 16))
        self.pw_entry.bind("<Return>", lambda e: self._submit())

        # Confirm Password (only for new vault)
        self.confirm_var = ctk.StringVar()
        self.confirm_entry = None

        if not vault_exists():
            ctk.CTkLabel(col, text="Confirm Password", font=(FONT, 13, "bold"), text_color=TEXT).pack(anchor="w", pady=(0, 6))
            
            self.confirm_entry = PasswordEntry(col, "Re-enter to confirm", var=self.confirm_var, show_strength=True)
            self.confirm_entry.pack(fill="x", pady=(0, 16))
            self.confirm_entry.bind("<Return>", lambda e: self._submit())

        # Error message
        self.err_var = ctk.StringVar()
        error_label = ctk.CTkLabel(col, textvariable=self.err_var, text_color=RED, font=(FONT, 12), height=30)
        error_label.pack()

        # Submit button
        action = "🔓 Create Vault" if not vault_exists() else "🔓 Unlock Vault"
        self.submit_btn = ctk.CTkButton(col, text=action, command=self._submit, height=45, fg_color=RED, hover_color=RED_HOV, 
                                        text_color="white", corner_radius=10, font=(FONT, 14, "bold"))
        self.submit_btn.pack(fill="x", pady=(10, 0))

        # Hint / forgot password
        if not vault_exists():
            ctk.CTkLabel(col, text="⚠️ Choose a strong password (min 8 characters)",
                         font=(FONT, 11), text_color=MUTED).pack(pady=(12, 0))
        else:
            ctk.CTkButton(col, text="Forgot password? Use a recovery code",
                          command=self._open_recovery,
                          fg_color="transparent", hover_color=BG,
                          text_color=MUTED, font=(FONT, 11, "underline"),
                          height=20, cursor="hand2").pack(pady=(12, 0))

        # Focus the password entry
        self.pw_entry.focus()

    def _open_recovery(self):
        RecoveryScreen(self, self._on_recovery_success)

    def _on_recovery_success(self, key: bytes, vault: dict):
        """Called after a successful recovery — open the vault normally."""
        self.place_forget()
        self.on_success(key, vault)

    def _submit(self):
        pw = self.pw_entry.get()
        if not pw:
            self.err_var.set("❌ Password cannot be empty.")
            return

        if not vault_exists():
            # Create new vault
            if pw != self.confirm_entry.get():
                self.err_var.set("❌ Passwords don't match.")
                return
            if len(pw) < 8:
                self.err_var.set("❌ Password must be at least 8 characters.")
                return

            try:
                salt = os.urandom(16)
                salt_b64 = base64.b64encode(salt).decode()
                master_key = derive_key(pw, salt)

                # Generate the vault key — this is what actually encrypts entries
                vault_key = generate_vault_key()
                wrapped = wrap_key(master_key, vault_key)

                init_vault(salt_b64, wrapped)
                vault = load_vault()

                # Generate recovery codes, each wrapping the vault key
                self._generate_recovery_codes(vault_key, vault)

                messagebox.showinfo("Success",
                    "Vault created successfully!\n\n"
                    "📋 Recovery codes have been generated.\n"
                    "Store them securely — they can restore full access\n"
                    "if you forget your master password.")
            except Exception as e:
                self.err_var.set("❌ Error creating vault.")
                return
        else:
            # Unlock existing vault
            try:
                vault = load_vault()
                salt = base64.b64decode(vault["salt"])
                master_key = derive_key(pw, salt)

                # Unwrap the vault key using the master key
                vault_key = unwrap_key(master_key, vault["vault_key"])
            except Exception:
                self.err_var.set("❌ Wrong password.")
                return

        self.place_forget()
        self.on_success(vault_key, vault)
    
    def _generate_recovery_codes(self, vault_key: bytes, vault: dict):
        """
        Generate 10 recovery codes. Each code gets its own salt and is used to
        derive a wrapping key that encrypts the vault key. This means any single
        code can unlock the vault without knowing the master password.
        """
        codes = []
        for _ in range(10):
            code = secrets.token_hex(4).upper()  # 8 hex chars = 32-bit entropy
            code_salt = os.urandom(16)
            code_key = derive_key(code, code_salt)
            wrapped_vault_key = wrap_key(code_key, vault_key)
            codes.append({
                "code": code,                                          # plaintext for display/verification
                "salt": base64.b64encode(code_salt).decode(),         # salt for key derivation
                "wrapped_vault_key": wrapped_vault_key,               # vault key encrypted under this code
                "used": False
            })

        vault["recovery_codes"] = codes
        save_vault(vault)

        # Show recovery codes in a dialog
        self._show_recovery_codes(codes)
    
    def _show_recovery_codes(self, codes):
        """Display recovery codes to the user."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("🔑 Recovery Codes")
        dialog.geometry("450x400")
        dialog.configure(fg_color=BG)
        dialog.grab_set()
        
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=24)
        
        ctk.CTkLabel(container, text="🔑 Recovery Codes", font=(FONT, 18, "bold"), 
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(container, 
                     text="Store these codes securely. Each can be used once\nto reset your master password.",
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(4, 16))
        
        # Code grid
        code_frame = ctk.CTkFrame(container, fg_color=CARD, corner_radius=8)
        code_frame.pack(fill="both", expand=True)
        
        for i, code_data in enumerate(codes):
            row = ctk.CTkFrame(code_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(row, text=f"{i+1:02d}.", font=(FONT, 13),
                         text_color=MUTED, width=30).pack(side="left")
            ctk.CTkLabel(row, text=code_data["code"], font=(FONT, 14, "bold"),
                         text_color=TEXT).pack(side="left", expand=True, anchor="w")
            ctk.CTkButton(row, text="Copy", width=52, height=26,
                          fg_color="transparent", hover_color=RED_DIM,
                          border_width=1, border_color=BORDER,
                          text_color=MUTED, corner_radius=6, font=(FONT, 11),
                          command=lambda c=code_data["code"]: pyperclip.copy(c)).pack(side="right")

        def _copy_all_creation():
            pyperclip.copy("\n".join(c["code"] for c in codes))

        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill="x", pady=(16, 0))

        ctk.CTkButton(btn_row, text="📋 Copy All", command=_copy_all_creation, height=40,
                      fg_color="transparent", hover_color=RED_DIM,
                      border_width=1, border_color=BORDER,
                      text_color=TEXT, corner_radius=8,
                      font=(FONT, 13, "bold")).pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(btn_row, text="I've Saved These Codes", command=dialog.destroy,
                      height=40, fg_color=RED, hover_color=RED_HOV,
                      text_color="white", corner_radius=8,
                      font=(FONT, 13, "bold")).pack(side="left", expand=True, fill="x")


# --- Main App ---

class MainApp(ctk.CTkFrame):
    def __init__(self, parent, key: bytes, vault: dict):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self.key = key
        self.vault = vault
        self._toast_job = None
        self._toast_lbl = None
        self._lock_timer = None
        self._lock_timeout = 300000  # 5 minutes default
        self._last_activity = time.time()
        
        # Bind activity tracking on the root Tk window (bind_all is blocked in CTkFrame)
        root = self._get_root()
        root.bind_all("<Key>", self._reset_auto_lock, add="+")
        root.bind_all("<Button>", self._reset_auto_lock, add="+")
        
        self._build()
        self._start_auto_lock_timer()

    def _build(self):
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._build_sidebar()
        self._build_panels()
        self._show("passwords")

    # --- Helpers ---

    def _get_root(self):
        """Walk up the widget tree to find the root Tk window."""
        widget = self
        while not isinstance(widget, ctk.CTk):
            widget = widget.master
        return widget

    # --- Auto-lock ---
    
    def _start_auto_lock_timer(self):
        """Start the auto-lock timer."""
        if self._lock_timer:
            self.after_cancel(self._lock_timer)
        self._lock_timer = self.after(1000, self._check_auto_lock)
    
    def _check_auto_lock(self):
        """Check if auto-lock should trigger."""
        if time.time() - self._last_activity > self._lock_timeout / 1000:
            self._lock()
        else:
            self._lock_timer = self.after(1000, self._check_auto_lock)
    
    def _reset_auto_lock(self, event=None):
        """Reset the auto-lock timer on user activity."""
        self._last_activity = time.time()

    # --- Sidebar ---

    def _build_sidebar(self):
        self.sb = ctk.CTkFrame(self, width=80, fg_color=SURFACE, corner_radius=0)
        self.sb.pack(side="left", fill="y")
        self.sb.pack_propagate(False)

        # Logo
        logo_area = ctk.CTkFrame(self.sb, fg_color="transparent", height=68)
        logo_area.pack(fill="x")
        logo_area.pack_propagate(False)
        ctk.CTkLabel(logo_area, text="V", font=(FONT, 24, "bold"), text_color=RED).place(relx=0.5, rely=0.5, anchor="center")

        # Separator
        ctk.CTkFrame(self.sb, height=1, fg_color=BORDER).pack(fill="x", padx=14, pady=8)

        # Navigation buttons
        self.sb_btns = {}
        nav_items = [("passwords", "🗝"), ("settings", "⚙")]
        for key_name, icon in nav_items:
            btn = ctk.CTkButton(self.sb, text=icon, width=48, height=48, fg_color="transparent", hover_color=RED_DIM, text_color=MUTED, 
                                font=(FONT, 22), corner_radius=8, command=lambda p=key_name: self._show(p))
            btn.pack(pady=4, padx=16)
            self.sb_btns[key_name] = btn

        # Lock button
        ctk.CTkFrame(self.sb, fg_color="transparent").pack(expand=True)
        ctk.CTkFrame(self.sb, height=1, fg_color=BORDER).pack(fill="x", padx=14)
        ctk.CTkButton(self.sb, text="⏻", width=48, height=48, fg_color="transparent", hover_color=RED_DIM, text_color=MUTED, 
                      font=(FONT, 22), corner_radius=8, command=self._lock).pack(pady=(8, 14), padx=16)

    def _show(self, panel: str):
        for name, btn in self.sb_btns.items():
            if name == panel:
                btn.configure(fg_color=RED_DIM, text_color=RED)
            else:
                btn.configure(fg_color="transparent", text_color=MUTED)
        
        for name, frame in self._panels.items():
            if name == panel:
                frame.pack(side="left", fill="both", expand=True)
            else:
                frame.pack_forget()
        
        self._reset_auto_lock()

    # --- Panels ---

    def _build_panels(self):
        self._panels = {
            "passwords": self._build_passwords_panel(),
            "settings": self._build_settings_panel()
        }

    # --- Passwords Panel ---

    def _build_passwords_panel(self):
        panel = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)

        # Header
        header = ctk.CTkFrame(panel, fg_color=SURFACE, corner_radius=0, height=96)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_row = ctk.CTkFrame(header, fg_color="transparent")
        title_row.pack(fill="x", padx=20, pady=(18, 8))

        ctk.CTkLabel(title_row, text="My Vault", font=(FONT, 16, "bold"), text_color=TEXT).pack(side="left")
        
        self.count_label = ctk.CTkLabel(title_row, text="0 entries", font=(FONT, 11), text_color=MUTED, fg_color=CARD, corner_radius=4, 
                                        padx=8, pady=2)
        self.count_label.pack(side="left", padx=(10, 0))

        # Search
        self.search_var = ctk.StringVar()
        self.search_var.trace("w", lambda *a: self._refresh_list())
        ctk.CTkEntry(header, height=34, placeholder_text="🔍 Search entries...", textvariable=self.search_var, fg_color=CARD, 
                     border_color=BORDER, border_width=1, corner_radius=6, text_color=TEXT, placeholder_text_color=MUTED, 
                     font=(FONT, 12)).pack(fill="x", padx=20, pady=(0, 8))

        # Separator
        ctk.CTkFrame(panel, height=1, fg_color=BORDER).pack(fill="x")

        # List - optimized scrolling
        self.list_frame = ctk.CTkScrollableFrame(panel, fg_color=BG, scrollbar_button_color=BORDER, scrollbar_button_hover_color=MUTED, 
                                                 orientation="vertical")
        self.list_frame.pack(fill="both", expand=True, padx=14, pady=14)

        # Footer
        footer = ctk.CTkFrame(panel, fg_color=SURFACE, corner_radius=0, height=62)
        footer.pack(fill="x")
        footer.pack_propagate(False)
        
        ctk.CTkButton(footer, text="+ Add Entry", command=self._open_add_dialog, height=36, fg_color=RED, hover_color=RED_HOV, 
                      text_color="white", corner_radius=8, font=(FONT, 13, "bold")).pack(fill="x", padx=16, pady=13)

        self._refresh_list()
        return panel

    def _refresh_list(self):
        # Clear
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        query = self.search_var.get().lower() if hasattr(self, "search_var") else ""
        entries = self.vault.get("entries", {})
        count = len(entries)

        if hasattr(self, "count_label"):
            self.count_label.configure(text=f"{count} {'entry' if count == 1 else 'entries'}")

        filtered = {k: v for k, v in entries.items() if not query or query in k.lower()}

        if not filtered:
            msg = "No results found." if query else "🔐 No entries yet.\nClick '+ Add Entry' to get started."
            ctk.CTkLabel(self.list_frame, text=msg, font=(FONT, 14), text_color=MUTED, justify="center").pack(pady=56)
            return

        # Batch create cards for better performance
        for service, data in filtered.items():
            self._create_card(service, data)

    def _create_card(self, service: str, data: dict):
        card = ctk.CTkFrame(self.list_frame, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER, height=64)
        card.pack(fill="x", pady=4)
        card.pack_propagate(False)
        card.columnconfigure(1, weight=1)

        # Icon
        ctk.CTkLabel(card, text=service[:2].upper(), width=40, height=40, fg_color=RED_DIM, text_color=RED, corner_radius=8, 
                     font=(FONT, 12, "bold")).grid(row=0, column=0, rowspan=2, padx=(14, 10), pady=12, sticky="ns")

        # Service name
        ctk.CTkLabel(card, text=service.title(), font=(FONT, 14, "bold"), text_color=TEXT, 
                     anchor="w" ).grid(row=0, column=1, sticky="sw", pady=(14, 1), padx=(0, 8))

        # Username
        ctk.CTkLabel(card, text=data["username"], font=(FONT, 12), text_color=MUTED, 
                     anchor="w").grid(row=1, column=1, sticky="nw", pady=(1, 14), padx=(0, 8))

        # Buttons
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.grid(row=0, column=2, rowspan=2, padx=(0, 14), pady=12, sticky="ns")

        # Copy button
        ctk.CTkButton(btn_frame, text="Copy", width=54, height=32, command=lambda s=service: self._copy_password(s), 
                      fg_color="transparent", hover_color=RED_DIM, border_width=1, border_color=BORDER, text_color=MUTED, 
                      corner_radius=6, font=(FONT, 11)).pack(side="left", padx=(0, 6))
        
        # Delete button
        ctk.CTkButton(btn_frame, text="✕", width=32, height=32, command=lambda s=service: self._delete_entry(s), 
                      fg_color="transparent", hover_color=RED_DIM, border_width=1, border_color=BORDER, text_color=MUTED, 
                      corner_radius=6, font=(FONT, 11)).pack(side="left")

    # --- Settings Panel ---

    def _build_settings_panel(self):
        panel = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)

        # Header
        header = ctk.CTkFrame(panel, fg_color=SURFACE, corner_radius=0, height=96)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="Settings", font=(FONT, 16, "bold"), text_color=TEXT).place(x=20, y=20)
        ctk.CTkLabel(header, text="Manage your vault preferences.", font=(FONT, 12), text_color=MUTED).place(x=20, y=46)

        # Separator
        ctk.CTkFrame(panel, height=1, fg_color=BORDER).pack(fill="x")

        # Body
        body = ctk.CTkScrollableFrame(panel, fg_color=BG, scrollbar_button_color=BORDER)
        body.pack(fill="both", expand=True, padx=16, pady=16)

        # Auto-lock section
        self._build_auto_lock_section(body)
        
        # Password Generator section
        self._build_generator_section(body)
        
        # Recovery section
        self._build_recovery_section(body)
        
        # Change password section
        self._build_change_password_section(body)
        
        # Vault info
        self.info_frame = ctk.CTkFrame(body, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
        self.info_frame.pack(fill="x")
        self._update_info_panel()

        return panel
    
    def _build_auto_lock_section(self, parent):
        section = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
        section.pack(fill="x", pady=(0, 14))
        
        section_top = ctk.CTkFrame(section, fg_color="transparent")
        section_top.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkLabel(section_top, text="⏱ Auto-Lock Timer", font=(FONT, 14, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(section_top, text="Lock the vault after inactivity.", font=(FONT, 12), 
                     text_color=MUTED).pack(anchor="w", pady=(3, 0))
        
        ctk.CTkFrame(section, height=1, fg_color=BORDER).pack(fill="x", padx=0, pady=12)
        
        form = ctk.CTkFrame(section, fg_color="transparent")
        form.pack(fill="x", padx=16, pady=(0, 16))
        
        ctk.CTkLabel(form, text="Lock after (minutes)", font=(FONT, 12), text_color=MUTED).pack(anchor="w")
        
        self.lock_time_var = ctk.StringVar(value=str(self._lock_timeout // 60000))
        lock_entry = ctk.CTkEntry(form, height=35, textvariable=self.lock_time_var, fg_color=CARD, 
                                  border_color=BORDER, border_width=1, corner_radius=6, text_color=TEXT,
                                  font=(FONT, 13), width=80)
        lock_entry.pack(side="left", pady=(4, 0))
        ctk.CTkLabel(form, text="minutes (0 = disabled)", font=(FONT, 12), text_color=MUTED).pack(side="left", padx=(8, 0))
        
        ctk.CTkButton(form, text="Apply", command=self._update_auto_lock, height=32, fg_color=RED, 
                      hover_color=RED_HOV, text_color="white", corner_radius=6, font=(FONT, 12, "bold"),
                      width=80).pack(side="right")
    
    def _build_generator_section(self, parent):
        section = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
        section.pack(fill="x", pady=(0, 14))

        section_top = ctk.CTkFrame(section, fg_color="transparent")
        section_top.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkLabel(section_top, text="🔑 Password Generator", font=(FONT, 14, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(section_top, text="Generate strong, random passwords.",
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(3, 0))

        ctk.CTkFrame(section, height=1, fg_color=BORDER).pack(fill="x", pady=12)

        form = ctk.CTkFrame(section, fg_color="transparent")
        form.pack(fill="x", padx=16, pady=(0, 16))

        # ── Row 1: Length label + Symbols checkbox side by side ──
        options_row = ctk.CTkFrame(form, fg_color="transparent")
        options_row.pack(fill="x", pady=(0, 8))

        # Length block
        length_block = ctk.CTkFrame(options_row, fg_color="transparent")
        length_block.pack(side="left", padx=(0, 24))
        ctk.CTkLabel(length_block, text="Length", font=(FONT, 12), text_color=MUTED).pack(anchor="w")
        self.gen_length_var = ctk.StringVar(value="20")
        ctk.CTkEntry(length_block, height=36, textvariable=self.gen_length_var,
                     fg_color=BG, border_color=BORDER, border_width=1,
                     corner_radius=6, text_color=TEXT, font=(FONT, 13), width=72).pack(anchor="w", pady=(4, 0))

        # Symbols block — vertically aligned with the entry
        symbols_block = ctk.CTkFrame(options_row, fg_color="transparent")
        symbols_block.pack(side="left", pady=(20, 0))
        self.gen_symbols_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(symbols_block, text="Include symbols",
                        variable=self.gen_symbols_var,
                        font=(FONT, 12), text_color=TEXT,
                        fg_color=RED, hover_color=RED_HOV,
                        corner_radius=4).pack(anchor="w")

        # ── Row 2: Generated password output ──
        ctk.CTkLabel(form, text="Generated Password", font=(FONT, 12), text_color=MUTED).pack(anchor="w")
        self.gen_result_var = ctk.StringVar()
        ctk.CTkEntry(form, height=40, textvariable=self.gen_result_var,
                     fg_color=BG, border_color=BORDER, border_width=1,
                     corner_radius=6, text_color=TEXT, font=(FONT, 13),
                     state="readonly").pack(fill="x", pady=(4, 12))

        # ── Row 3: Buttons ──
        btn_row = ctk.CTkFrame(form, fg_color="transparent")
        btn_row.pack(fill="x")

        ctk.CTkButton(btn_row, text="Generate", command=self._generate_password_demo,
                      height=38, fg_color=RED, hover_color=RED_HOV,
                      text_color="white", corner_radius=6,
                      font=(FONT, 12, "bold")).pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(btn_row, text="Copy", command=self._copy_generated_password,
                      height=38, fg_color="transparent", hover_color=RED_DIM,
                      border_width=1, border_color=BORDER,
                      text_color=MUTED, corner_radius=6,
                      font=(FONT, 12, "bold")).pack(side="left", expand=True, fill="x")
    
    def _build_recovery_section(self, parent):
        section = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
        section.pack(fill="x", pady=(0, 14))
        
        section_top = ctk.CTkFrame(section, fg_color="transparent")
        section_top.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkLabel(section_top, text="🔑 Recovery Options", font=(FONT, 14, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(section_top, text="Recovery codes can restore access if you forget your master password.", 
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(3, 0))
        
        ctk.CTkFrame(section, height=1, fg_color=BORDER).pack(fill="x", padx=0, pady=12)
        
        form = ctk.CTkFrame(section, fg_color="transparent")
        form.pack(fill="x", padx=16, pady=(0, 16))
        
        btn_row = ctk.CTkFrame(form, fg_color="transparent")
        btn_row.pack(fill="x")
        
        ctk.CTkButton(btn_row, text="📋 Show Recovery Codes", command=self._show_recovery_codes, height=38,
                      fg_color="transparent", hover_color=RED_DIM, border_width=1, border_color=BORDER,
                      text_color=TEXT, corner_radius=6, font=(FONT, 12, "bold")).pack(side="left", padx=(0, 8))
        
        ctk.CTkButton(btn_row, text="🔄 Generate New Codes", command=self._regenerate_recovery_codes, height=38,
                      fg_color=RED, hover_color=RED_HOV, text_color="white", corner_radius=6, 
                      font=(FONT, 12, "bold")).pack(side="left")
    
    def _build_change_password_section(self, parent):
        section = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=8, border_width=1, border_color=BORDER)
        section.pack(fill="x", pady=(0, 14))

        section_top = ctk.CTkFrame(section, fg_color="transparent")
        section_top.pack(fill="x", padx=16, pady=(16, 0))
        ctk.CTkLabel(section_top, text="Change Master Password", font=(FONT, 14, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(section_top, text="Re-encrypts all entries with your new password.", font=(FONT, 12), 
                     text_color=MUTED).pack(anchor="w", pady=(3, 0))

        ctk.CTkFrame(section, height=1, fg_color=BORDER).pack(fill="x", padx=0, pady=12)

        form = ctk.CTkFrame(section, fg_color="transparent")
        form.pack(fill="x", padx=16, pady=(0, 16))

        self.cur_pw_var = ctk.StringVar()
        self.new_pw_var = ctk.StringVar()
        self.conf_pw_var = ctk.StringVar()

        # Current password
        ctk.CTkLabel(form, text="Current Password", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        cur_pw = PasswordEntry(form, "enter your current password", var=self.cur_pw_var)
        cur_pw.pack(fill="x", pady=(0, 8))

        # New password with strength meter
        ctk.CTkLabel(form, text="New Password", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        new_pw = PasswordEntry(form, "choose a strong new password", var=self.new_pw_var, show_strength=True)
        new_pw.pack(fill="x", pady=(0, 8))

        # Confirm password
        ctk.CTkLabel(form, text="Confirm New Password", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        conf_pw = PasswordEntry(form, "re-enter the new password", var=self.conf_pw_var, show_strength=True)
        conf_pw.pack(fill="x", pady=(0, 8))

        self.pw_change_err = ctk.StringVar()
        ctk.CTkLabel(form, textvariable=self.pw_change_err, text_color=RED, font=(FONT, 11), height=18).pack(anchor="w")

        ctk.CTkButton(form, text="Update Password", command=self._change_password, height=38, fg_color=RED, hover_color=RED_HOV, 
                      text_color="white", corner_radius=6, font=(FONT, 13, "bold")).pack(fill="x", pady=(8, 0))
    
    def _update_auto_lock(self):
        """Update the auto-lock timeout."""
        try:
            minutes = int(self.lock_time_var.get())
            if minutes < 0:
                raise ValueError
            self._lock_timeout = minutes * 60000
            self._start_auto_lock_timer()
            self._toast(f"Auto-lock set to {minutes} minutes.")
        except ValueError:
            self._toast("Please enter a valid number (0 = disabled).")
    
    def _generate_password_demo(self):
        """Generate and display a password in settings."""
        try:
            length = int(self.gen_length_var.get())
            length = max(8, min(64, length))
        except ValueError:
            length = 20
        
        use_symbols = self.gen_symbols_var.get()
        password = generate_password(length, use_symbols)
        self.gen_result_var.set(password)
    
    def _copy_generated_password(self):
        """Copy the generated password to clipboard."""
        password = self.gen_result_var.get()
        if password:
            pyperclip.copy(password)
            self._toast("Generated password copied to clipboard.")
    
    def _show_recovery_codes(self):
        """Display recovery codes to the user."""
        codes = self.vault.get("recovery_codes", [])
        if not codes:
            messagebox.showinfo("No Codes", "No recovery codes found. Generate new ones.")
            return

        # Codes are stored as plaintext — no decryption needed
        decrypted_codes = [
            {"code": c.get("code", "—") if not c["used"] else "—", "used": c["used"]}
            for c in codes
        ]

        dialog = ctk.CTkToplevel(self)
        dialog.title("🔑 Recovery Codes")
        dialog.geometry("450x450")
        dialog.configure(fg_color=BG)
        dialog.grab_set()
        
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=24)
        
        ctk.CTkLabel(container, text="🔑 Recovery Codes", font=(FONT, 18, "bold"), 
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(container, 
                     text="Each code can be used once to reset your master password.",
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(4, 16))
        
        # Code grid
        code_frame = ctk.CTkScrollableFrame(container, fg_color=CARD, corner_radius=8)
        code_frame.pack(fill="both", expand=True)
        
        for i, code_data in enumerate(decrypted_codes):
            row = ctk.CTkFrame(code_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=4)

            status = "✅" if not code_data["used"] else "❌ Used"
            status_color = SUCCESS if not code_data["used"] else MUTED
            is_used = code_data["used"]

            ctk.CTkLabel(row, text=f"{i+1:02d}.", font=(FONT, 13),
                         text_color=MUTED, width=30).pack(side="left")
            ctk.CTkLabel(row, text=code_data["code"], font=(FONT, 14, "bold"),
                         text_color=TEXT if not is_used else MUTED).pack(side="left", padx=(0, 10))
            ctk.CTkLabel(row, text=status, font=(FONT, 11),
                         text_color=status_color).pack(side="left", expand=True, anchor="w")
            if not is_used:
                ctk.CTkButton(row, text="Copy", width=52, height=26,
                              fg_color="transparent", hover_color=RED_DIM,
                              border_width=1, border_color=BORDER,
                              text_color=MUTED, corner_radius=6, font=(FONT, 11),
                              command=lambda c=code_data["code"]: pyperclip.copy(c)).pack(side="right")

        def _copy_all_settings():
            available = [c["code"] for c in decrypted_codes if not c["used"]]
            if available:
                pyperclip.copy("\n".join(available))

        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill="x", pady=(16, 0))

        ctk.CTkButton(btn_row, text="📋 Copy Unused", command=_copy_all_settings, height=40,
                      fg_color="transparent", hover_color=RED_DIM,
                      border_width=1, border_color=BORDER,
                      text_color=TEXT, corner_radius=8,
                      font=(FONT, 13, "bold")).pack(side="left", expand=True, fill="x", padx=(0, 8))

        ctk.CTkButton(btn_row, text="Close", command=dialog.destroy,
                      height=40, fg_color=RED, hover_color=RED_HOV,
                      text_color="white", corner_radius=8,
                      font=(FONT, 13, "bold")).pack(side="left", expand=True, fill="x")
    
    def _regenerate_recovery_codes(self):
        """Generate new recovery codes, each wrapping the vault key."""
        if not messagebox.askyesno("Regenerate Codes",
                                   "This will invalidate all existing recovery codes.\n"
                                   "Are you sure you want to continue?"):
            return

        codes = []
        for _ in range(10):
            code = secrets.token_hex(4).upper()
            code_salt = os.urandom(16)
            code_key = derive_key(code, code_salt)
            wrapped_vault_key = wrap_key(code_key, self.key)
            codes.append({
                "code": code,
                "salt": base64.b64encode(code_salt).decode(),
                "wrapped_vault_key": wrapped_vault_key,
                "used": False
            })

        self.vault["recovery_codes"] = codes
        save_vault(self.vault)

        # Show new codes
        self._show_recovery_codes()
        self._toast("New recovery codes generated.")
    
    def _update_info_panel(self):
        # Clear existing widgets
        for widget in self.info_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.info_frame, text="Vault Info", font=(FONT, 14, "bold"), 
                     text_color=TEXT).pack(anchor="w", padx=16, pady=(16, 4))
        
        ctk.CTkFrame(self.info_frame, height=1, fg_color=BORDER).pack(fill="x")

        count = len(self.vault.get("entries", {}))
        recovery_count = len(self.vault.get("recovery_codes", []))
        created_at = self.vault.get("created_at", "Unknown")
        
        for key, value in [
            ("Encryption", "AES-256-GCM"),
            ("KDF", "PBKDF2-SHA256 · 600,000 iterations"),
            ("Entries", str(count)),
            ("Recovery Codes", str(recovery_count)),
            ("Vault Created", created_at[:10] if created_at != "Unknown" else "Unknown"),
            ("Vault file", "vault.json (local only)"),
        ]:
            row = ctk.CTkFrame(self.info_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=5)
            ctk.CTkLabel(row, text=key, font=(FONT, 12), text_color=MUTED).pack(side="left")
            ctk.CTkLabel(row, text=value, font=(FONT, 12), text_color=TEXT).pack(side="right")

        ctk.CTkFrame(self.info_frame, fg_color="transparent", height=12).pack()

    def _change_password(self):
        current = self.cur_pw_var.get()
        new = self.new_pw_var.get()
        confirm = self.conf_pw_var.get()

        if not current or not new or not confirm:
            self.pw_change_err.set("All fields are required.")
            return
        if new != confirm:
            self.pw_change_err.set("New passwords don't match.")
            return
        if len(new) < 8:
            self.pw_change_err.set("Password must be at least 8 characters.")
            return

        vault = load_vault()
        salt = base64.b64decode(vault["salt"])
        try:
            old_master_key = derive_key(current, salt)
            # Verify by unwrapping the vault key — raises if password is wrong
            vault_key = unwrap_key(old_master_key, vault["vault_key"])
        except Exception:
            self.pw_change_err.set("Current password is wrong.")
            return

        # New master key wraps the SAME vault key — entries need no changes at all
        new_salt = os.urandom(16)
        new_master_key = derive_key(new, new_salt)
        vault["salt"] = base64.b64encode(new_salt).decode()
        vault["vault_key"] = wrap_key(new_master_key, vault_key)
        # Recovery codes keep their own wrapped vault keys unchanged
        save_vault(vault)

        self.vault = vault
        # self.key is already the vault_key and hasn't changed

        self.cur_pw_var.set("")
        self.new_pw_var.set("")
        self.conf_pw_var.set("")
        self.pw_change_err.set("")

        self._update_info_panel()
        self._refresh_list()
        self._toast("Master password updated successfully.")

    # --- Actions ---

    def _copy_password(self, service: str):
        try:
            password = decrypt(self.key, self.vault["entries"][service]["password"])
            pyperclip.copy(password)
            self._toast(f"'{service}' password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def _delete_entry(self, service: str):
        if messagebox.askyesno("Delete entry", f"Delete '{service}'?\nThis cannot be undone."):
            del self.vault["entries"][service]
            save_vault(self.vault)
            self._refresh_list()
            self._update_info_panel()

    def _open_add_dialog(self):
        AddEntryDialog(self, self.key, self.vault, self._refresh_list, self._update_info_panel)

    def _lock(self):
        # Cancel timer and remove root-level bindings before hiding
        if self._lock_timer:
            self.after_cancel(self._lock_timer)
            self._lock_timer = None
        root = self._get_root()
        root.unbind_all("<Key>")
        root.unbind_all("<Button>")
        self.place_forget()
        LoginScreen(self.master, lambda k, v: MainApp(self.master, k, v))

    def _toast(self, msg: str):
        if self._toast_lbl is None:
            self._toast_lbl = ctk.CTkLabel(self, text="", font=(FONT, 11), text_color=SUCCESS, fg_color="#0d1f16", corner_radius=6, 
                                           padx=14, pady=7)
        self._toast_lbl.configure(text=msg)
        self._toast_lbl.place(relx=0.5, rely=0.97, anchor="s")
        if self._toast_job:
            self.after_cancel(self._toast_job)
        self._toast_job = self.after(2800, self._toast_lbl.place_forget)


# --- Add Entry Dialog ---

class AddEntryDialog(ctk.CTkToplevel):
    def __init__(self, parent, key, vault, on_save, on_update_info):
        super().__init__(parent)
        self.key = key
        self.vault = vault
        self.on_save = on_save
        self.on_update_info = on_update_info
        self.title("New Entry")
        self.geometry("440x540")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.grab_set()
        self._build()

    def _build(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=24)

        ctk.CTkLabel(container, text="New Entry", font=(FONT, 18, "bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(container, text="All fields are required.", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(3, 16))

        self.svc_var = ctk.StringVar()
        self.usr_var = ctk.StringVar()
        self.pw_var = ctk.StringVar()

        # Service
        ctk.CTkLabel(container, text="Service", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        ctk.CTkEntry(container, height=40, placeholder_text="e.g. github, netflix, spotify", textvariable=self.svc_var, fg_color=CARD, 
                     border_color=BORDER, border_width=1, corner_radius=6, text_color=TEXT, placeholder_text_color=MUTED, 
                     font=(FONT, 13)).pack(fill="x", pady=(0, 8))

        # Username
        ctk.CTkLabel(container, text="Username", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        ctk.CTkEntry(container, height=40, placeholder_text="your username or email", textvariable=self.usr_var, fg_color=CARD, 
                     border_color=BORDER, border_width=1, corner_radius=6, text_color=TEXT, placeholder_text_color=MUTED, 
                     font=(FONT, 13)).pack(fill="x", pady=(0, 8))

        # Password with toggle and generator
        ctk.CTkLabel(container, text="Password", font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(8, 4))
        self.pw_entry = PasswordEntry(container, "enter the password", var=self.pw_var, show_strength=True)
        self.pw_entry.pack(fill="x", pady=(0, 8))
        self.pw_entry.add_generate_button()

        self.err_var = ctk.StringVar()
        ctk.CTkLabel(container, textvariable=self.err_var, text_color=RED, font=(FONT, 11), height=18).pack(anchor="w", pady=(4, 0))

        ctk.CTkButton(container, text="Save Entry", command=self._save, height=40, fg_color=RED, hover_color=RED_HOV, 
                      text_color="white", corner_radius=6, font=(FONT, 13, "bold")).pack(fill="x", pady=(8, 0))

    def _save(self):
        service = self.svc_var.get().strip().lower()
        username = self.usr_var.get().strip()
        password = self.pw_var.get()

        if not service or not username or not password:
            self.err_var.set("All fields are required.")
            return
        if service in self.vault["entries"]:
            self.err_var.set(f"'{service}' already exists.")
            return

        self.vault["entries"][service] = {
            "username": username,
            "password": encrypt(self.key, password)
        }
        save_vault(self.vault)
        self.on_save()
        self.on_update_info()
        self.destroy()


# --- Recovery Login (for forgotten password) ---

class RecoveryScreen(ctk.CTkToplevel):
    """
    Two-step recovery:
      Step 1 – Enter a recovery code to prove ownership.
      Step 2 – Set a new master password; vault is re-encrypted and opened.

    Because the old master password is unknown, existing entries cannot be
    decrypted and are preserved as-is (still encrypted under the old key).
    The user will be warned, and they can delete those entries from the vault.
    Recovery codes themselves are not encrypted under the master key by design —
    they are stored with a plaintext "code" field so verification works without
    the old password.
    """

    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.on_success = on_success   # callable(key, vault)
        self._verified_code_index = None
        self._vault = None
        self._vault_key = None

        self.title("🔑 Account Recovery")
        self.geometry("460x420")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.grab_set()

        self._frame = None
        self._show_step1()

    # ── Step 1: verify recovery code ──────────────────────────────────────

    def _show_step1(self):
        if self._frame:
            self._frame.destroy()
        self._frame = ctk.CTkFrame(self, fg_color="transparent")
        self._frame.pack(fill="both", expand=True, padx=28, pady=28)

        ctk.CTkLabel(self._frame, text="🔑 Account Recovery", font=(FONT, 18, "bold"),
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(self._frame,
                     text="Step 1 of 2  —  Enter one of your recovery codes.",
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(4, 20))

        ctk.CTkLabel(self._frame, text="Recovery Code", font=(FONT, 12), text_color=MUTED).pack(anchor="w")
        self.code_var = ctk.StringVar()
        code_entry = ctk.CTkEntry(self._frame, height=42,
                                  placeholder_text="e.g. A1B2C3D4",
                                  textvariable=self.code_var,
                                  fg_color=CARD, border_color=BORDER, border_width=1,
                                  corner_radius=8, text_color=TEXT,
                                  placeholder_text_color=MUTED, font=(FONT, 15, "bold"))
        code_entry.pack(fill="x", pady=(6, 4))
        code_entry.bind("<Return>", lambda e: self._verify_code())
        code_entry.focus()

        self.step1_err = ctk.StringVar()
        ctk.CTkLabel(self._frame, textvariable=self.step1_err, text_color=RED,
                     font=(FONT, 11), height=20).pack(anchor="w", pady=(2, 0))

        ctk.CTkButton(self._frame, text="Verify Code →", command=self._verify_code,
                      height=42, fg_color=RED, hover_color=RED_HOV,
                      text_color="white", corner_radius=8,
                      font=(FONT, 13, "bold")).pack(fill="x", pady=(12, 0))

        ctk.CTkButton(self._frame, text="Cancel", command=self.destroy,
                      height=34, fg_color="transparent", hover_color=RED_DIM,
                      text_color=MUTED, corner_radius=6,
                      font=(FONT, 12)).pack(pady=(8, 0))

    def _verify_code(self):
        code = self.code_var.get().strip().upper()
        if not code:
            self.step1_err.set("Please enter a recovery code.")
            return

        vault = load_vault()
        recovery_codes = vault.get("recovery_codes", [])

        for i, code_data in enumerate(recovery_codes):
            if code_data["used"]:
                continue
            stored = code_data.get("code", "").strip().upper()
            if not stored or stored != code:
                continue
            # Code string matched — now cryptographically verify by unwrapping the vault key
            try:
                code_salt = base64.b64decode(code_data["salt"])
                code_key = derive_key(code, code_salt)
                vault_key = unwrap_key(code_key, code_data["wrapped_vault_key"])
            except Exception:
                self.step1_err.set("Invalid or already used recovery code.")
                return
            self._verified_code_index = i
            self._vault = vault
            self._vault_key = vault_key
            self._show_step2()
            return

        self.step1_err.set("Invalid or already used recovery code.")

    # ── Step 2: set new master password ───────────────────────────────────

    def _show_step2(self):
        if self._frame:
            self._frame.destroy()
        self._frame = ctk.CTkFrame(self, fg_color="transparent")
        self._frame.pack(fill="both", expand=True, padx=28, pady=28)

        ctk.CTkLabel(self._frame, text="🔑 Account Recovery", font=(FONT, 18, "bold"),
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(self._frame,
                     text="Step 2 of 2  —  Set your new master password.",
                     font=(FONT, 12), text_color=MUTED).pack(anchor="w", pady=(4, 4))

        entry_count = len(self._vault.get("entries", {}))
        info = ctk.CTkFrame(self._frame, fg_color=CARD, corner_radius=8)
        info.pack(fill="x", pady=(4, 16))
        ctk.CTkLabel(info,
                     text=f"✅  Your {entry_count} saved {'entry' if entry_count == 1 else 'entries'} will be fully restored.",
                     font=(FONT, 11), text_color=SUCCESS, justify="left").pack(padx=12, pady=10)

        self.new_pw_var = ctk.StringVar()
        self.conf_pw_var = ctk.StringVar()

        ctk.CTkLabel(self._frame, text="New Master Password", font=(FONT, 12),
                     text_color=MUTED).pack(anchor="w")
        self.new_pw_entry = PasswordEntry(self._frame, "choose a strong password",
                                          var=self.new_pw_var, show_strength=True)
        self.new_pw_entry.pack(fill="x", pady=(6, 10))

        ctk.CTkLabel(self._frame, text="Confirm Password", font=(FONT, 12),
                     text_color=MUTED).pack(anchor="w")
        self.conf_pw_entry = PasswordEntry(self._frame, "re-enter your new password",
                                           var=self.conf_pw_var)
        self.conf_pw_entry.pack(fill="x", pady=(6, 4))
        self.conf_pw_entry.bind("<Return>", lambda e: self._set_new_password())

        self.step2_err = ctk.StringVar()
        ctk.CTkLabel(self._frame, textvariable=self.step2_err, text_color=RED,
                     font=(FONT, 11), height=20).pack(anchor="w", pady=(2, 0))

        ctk.CTkButton(self._frame, text="Reset & Open Vault ✓", command=self._set_new_password,
                      height=42, fg_color=RED, hover_color=RED_HOV,
                      text_color="white", corner_radius=8,
                      font=(FONT, 13, "bold")).pack(fill="x", pady=(10, 0))

    def _set_new_password(self):
        new_pw = self.new_pw_var.get()
        conf_pw = self.conf_pw_var.get()

        if not new_pw:
            self.step2_err.set("Password cannot be empty.")
            return
        if len(new_pw) < 8:
            self.step2_err.set("Password must be at least 8 characters.")
            return
        if new_pw != conf_pw:
            self.step2_err.set("Passwords don't match.")
            return

        vault = self._vault

        # Mark recovery code as used
        vault["recovery_codes"][self._verified_code_index]["used"] = True

        # Wrap the recovered vault key under the new master password
        new_salt = os.urandom(16)
        new_master_key = derive_key(new_pw, new_salt)
        vault["salt"] = base64.b64encode(new_salt).decode()
        vault["vault_key"] = wrap_key(new_master_key, self._vault_key)

        # Entries are untouched — they were always encrypted under the vault key,
        # which we recovered from the recovery code. Full access is restored.

        save_vault(vault)

        self.destroy()
        # Pass the vault_key (not master key) — this is what decrypts entries
        self.on_success(self._vault_key, vault)


# --- Root ---

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VaultX")
        self.geometry("600x650")
        self.minsize(600, 650)
        self.resizable(False, False)
        self.configure(fg_color=BG)

        try:
            self.iconbitmap("vault.ico")
        except Exception:
            pass

        LoginScreen(self, lambda key, vault: MainApp(self, key, vault))


if __name__ == "__main__":
    App().mainloop()