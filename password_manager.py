import os
import json
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox
import string
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pyperclip

SALT_FILE = "salt.bin"
DATA_FILE = "vault.enc"


def generate_password(length: int = 16) -> str:
    """Return a random password of the given length."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_vault(fernet: Fernet) -> dict:
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted data.")
        raise SystemExit


def save_vault(fernet: Fernet, vault: dict) -> None:
    data = json.dumps(vault).encode()
    encrypted = fernet.encrypt(data)
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)


def prompt_master_password() -> str:
    root = tk.Tk()
    root.withdraw()
    pwd = simpledialog.askstring("Master Password", "Enter master password:", show="*")
    root.destroy()
    if pwd is None:
        raise SystemExit
    return pwd


def setup_master_password() -> str:
    """Prompt the user to create an initial master password."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Set Master Password",
        "Initial setup: please create a master password.",
    )

    dialog = tk.Toplevel(root)
    dialog.title("Set Master Password")
    tk.Label(dialog, text="Master password:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(dialog, text="Confirm password:").grid(row=1, column=0, padx=5, pady=5)

    pwd_var = tk.StringVar()
    confirm_var = tk.StringVar()
    tk.Entry(dialog, textvariable=pwd_var, show="*").grid(row=0, column=1, padx=5, pady=5)
    tk.Entry(dialog, textvariable=confirm_var, show="*").grid(row=1, column=1, padx=5, pady=5)

    def fill_generated() -> None:
        pw = generate_password()
        pwd_var.set(pw)
        confirm_var.set(pw)

    def on_ok() -> None:
        p1 = pwd_var.get()
        p2 = confirm_var.get()
        if p1 and p1 == p2:
            dialog.destroy()
        else:
            messagebox.showerror("Error", "Passwords do not match or are empty.")

    tk.Button(dialog, text="Generate", command=fill_generated).grid(row=2, column=0, padx=5, pady=5)
    tk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, padx=5, pady=5)

    dialog.grab_set()
    root.wait_window(dialog)
    password = pwd_var.get()
    if not password:
        root.destroy()
        raise SystemExit
    root.destroy()
    return password


def get_or_create_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def add_entry(vault: dict, listbox: tk.Listbox) -> None:
    dialog = tk.Toplevel()
    dialog.title("Add Entry")
    tk.Label(dialog, text="Service:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(dialog, text="Password:").grid(row=1, column=0, padx=5, pady=5)

    service_var = tk.StringVar()
    password_var = tk.StringVar()
    tk.Entry(dialog, textvariable=service_var).grid(row=0, column=1, padx=5, pady=5)
    tk.Entry(dialog, textvariable=password_var, show="*").grid(row=1, column=1, padx=5, pady=5)

    def fill_generated() -> None:
        password_var.set(generate_password())

    def on_ok():
        service = service_var.get().strip()
        password = password_var.get()
        if service:
            vault[service] = password
            listbox.insert(tk.END, service)
        dialog.destroy()

    tk.Button(dialog, text="Generate", command=fill_generated).grid(row=2, column=0, padx=5, pady=5)
    tk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, padx=5, pady=5)
    dialog.grab_set()
    dialog.wait_window()


def copy_password(vault: dict, listbox: tk.Listbox) -> None:
    selection = listbox.curselection()
    if not selection:
        return
    service = listbox.get(selection[0])
    pyperclip.copy(vault[service])
    messagebox.showinfo("Copied", f"Password for '{service}' copied to clipboard.")


def delete_entry(vault: dict, listbox: tk.Listbox) -> None:
    selection = listbox.curselection()
    if not selection:
        return
    service = listbox.get(selection[0])
    if messagebox.askyesno("Delete", f"Delete entry '{service}'?"):
        listbox.delete(selection[0])
        vault.pop(service, None)


def main() -> None:
    first_run = not (os.path.exists(DATA_FILE) and os.path.exists(SALT_FILE))

    if first_run:
        password = setup_master_password()
        salt = get_or_create_salt()
        key = derive_key(password, salt)
        fernet = Fernet(key)
        vault = {}
        save_vault(fernet, vault)
    else:
        password = prompt_master_password()
        salt = get_or_create_salt()
        key = derive_key(password, salt)
        fernet = Fernet(key)
        vault = load_vault(fernet)

    root = tk.Tk()
    root.title("LPM")

    listbox = tk.Listbox(root, width=40)
    listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    for service in vault:
        listbox.insert(tk.END, service)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    tk.Button(button_frame, text="Add", command=lambda: add_entry(vault, listbox)).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Copy", command=lambda: copy_password(vault, listbox)).grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Delete", command=lambda: delete_entry(vault, listbox)).grid(row=0, column=2, padx=5)

    def on_close():
        save_vault(fernet, vault)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
