import os
import json
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, PhotoImage
import string
import secrets
import sys
import subprocess
import platform
import shutil
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pyperclip

SALT_FILE = "salt.bin"
DATA_FILE = "vault.enc"

def ensure_gui() -> None:
    """Exit if Tkinter cannot access a display."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
    except tk.TclError as exc:
        print("Error: Tkinter could not open a window. Is a graphical environment available?")
        raise SystemExit(1) from exc


def center_window(window, width=None, height=None):
    """Center a window on the screen."""
    window.update_idletasks()
    if width is None:
        width = window.winfo_reqwidth()
    if height is None:
        height = window.winfo_reqheight()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")


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
    dialog = tk.Toplevel(root)
    dialog.title("Master Password")
    dialog.geometry("310x110")
    dialog.resizable(False, False)
    center_window(dialog, 310, 110)
    
    # Set rounded icon
    set_window_icon(dialog)
    
    tk.Label(dialog, text="Enter master password:").grid(row=0, column=0, padx=5, pady=5)

    pwd_var = tk.StringVar()
    pwd_entry = tk.Entry(dialog, textvariable=pwd_var, show="*", width=14)
    pwd_entry.grid(row=0, column=1, padx=(5,30), pady=5)

    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        pwd_entry.config(show="" if show_var.get() else "*")
    show_cb = tk.Checkbutton(dialog, text="Show Password", variable=show_var, command=toggle_show)
    show_cb.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

    def on_ok():
        dialog.destroy()
    tk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    dialog.grab_set()
    root.wait_window(dialog)
    pwd = pwd_var.get()
    root.destroy()
    if pwd is None or pwd == "":
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
    dialog.geometry("350x250")
    dialog.resizable(False, False)
    center_window(dialog, 350, 250)
    
    # Set rounded icon
    set_window_icon(dialog)
    
    tk.Label(dialog, text="Master password:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(dialog, text="Confirm password:").grid(row=1, column=0, padx=5, pady=5)

    pwd_var = tk.StringVar()
    confirm_var = tk.StringVar()
    pwd_entry = tk.Entry(dialog, textvariable=pwd_var, show="*")
    pwd_entry.grid(row=0, column=1, padx=5, pady=5)
    confirm_entry = tk.Entry(dialog, textvariable=confirm_var, show="*")
    confirm_entry.grid(row=1, column=1, padx=5, pady=5)

    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        show = "" if show_var.get() else "*"
        pwd_entry.config(show=show)
        confirm_entry.config(show=show)
    show_cb = tk.Checkbutton(dialog, text="Show Password", variable=show_var, command=toggle_show)
    show_cb.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

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

    tk.Button(dialog, text="Generate", command=fill_generated).grid(row=3, column=0, padx=5, pady=5)
    tk.Button(dialog, text="OK", command=on_ok).grid(row=3, column=1, padx=5, pady=5)

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
    dialog.geometry("325x180")
    dialog.resizable(False, False)
    center_window(dialog, 325, 180)
    
    # Set rounded icon
    set_window_icon(dialog)
    
    tk.Label(dialog, text="Service:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(dialog, text="Password:").grid(row=1, column=0, padx=5, pady=5)

    service_var = tk.StringVar()
    password_var = tk.StringVar()
    tk.Entry(dialog, textvariable=service_var, width=20).grid(row=0, column=1, padx=5, pady=5)
    pwd_entry = tk.Entry(dialog, textvariable=password_var, show="*", width=20)
    pwd_entry.grid(row=1, column=1, padx=5, pady=5)

    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        pwd_entry.config(show="" if show_var.get() else "*")
    show_cb = tk.Checkbutton(dialog, text="Show Password", variable=show_var, command=toggle_show)
    show_cb.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def fill_generated() -> None:
        password_var.set(generate_password())

    def on_ok():
        service = service_var.get().strip()
        password = password_var.get()
        if service:
            vault[service] = password
            listbox.insert(tk.END, service)
        dialog.destroy()

    tk.Button(dialog, text="Generate", command=fill_generated).grid(row=3, column=0, padx=5, pady=5)
    tk.Button(dialog, text="OK", command=on_ok).grid(row=3, column=1, padx=5, pady=5)
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


def show_startup_screen() -> None:
    """Display a startup screen for 1.5 seconds."""
    root = tk.Tk()
    root.title("LPM")
    root.geometry("400x200")
    root.resizable(False, False)
    center_window(root, 400, 200)
    
    # Set rounded icon
    set_window_icon(root)
    
    # Create main label
    label = tk.Label(root, text="LPM: Simple encrypted local password manager.", 
                    font=("Arial", 14, "bold"), wraplength=350)
    label.pack(expand=True)
    
    # Auto-close after 1.5 seconds
    root.after(1500, root.destroy)
    root.mainloop()


def open_backup_folder():
    """Open the folder containing vault.enc and salt.bin."""
    folder = os.path.abspath(os.path.dirname(DATA_FILE))
    if sys.platform.startswith("darwin"):
        subprocess.Popen(["open", folder])
    elif sys.platform.startswith("win"):
        os.startfile(folder)
    else:
        subprocess.Popen(["xdg-open", folder])


def find_usb_drives():
    drives = []
    if sys.platform.startswith("darwin"):
        # macOS: USB drives are typically in /Volumes, skip system volumes
        for vol in os.listdir("/Volumes"):
            path = os.path.join("/Volumes", vol)
            if os.path.ismount(path) and vol not in ("Macintosh HD", "MacintoshHD", "Recovery"):  # skip system
                drives.append(path)
    elif sys.platform.startswith("win"):
        # Windows: check all drive letters
        import string
        from ctypes import windll
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive = f"{letter}:\\"
                # Check if removable
                if windll.kernel32.GetDriveTypeW(drive) == 2:
                    drives.append(drive)
            bitmask >>= 1
    return drives

def usb_backup():
    drives = find_usb_drives()
    if not drives:
        messagebox.showerror("USB Backup", "No USB drives detected. Please insert a USB drive and try again.")
        return
    drive = drives[0]
    if len(drives) > 1:
        # Prompt user to select a drive
        import tkinter.simpledialog
        drive = tkinter.simpledialog.askstring("Select USB Drive", f"Multiple USB drives found:\n" + "\n".join(drives) + "\nEnter path/letter:", initialvalue=drives[0])
        if not drive or drive not in drives:
            messagebox.showerror("USB Backup", "Invalid or no drive selected.")
            return
    
    # Validate drive path
    if not os.path.exists(drive):
        messagebox.showerror("USB Backup", f"Drive path does not exist: {drive}")
        return
    
    backup_dir = os.path.join(drive, "LPM_BACKUP")
    print(f"Drive: {drive}")
    print(f"Backup directory: {backup_dir}")
    
    try:
        os.makedirs(backup_dir, exist_ok=True)
        print(f"Created backup directory: {backup_dir}")
        
        # Check if source files exist
        if not os.path.exists("salt.bin"):
            messagebox.showerror("USB Backup", "salt.bin not found in current directory")
            return
        if not os.path.exists("vault.enc"):
            messagebox.showerror("USB Backup", "vault.enc not found in current directory")
            return
            
        # Add a small delay to ensure files are not being actively written
        time.sleep(0.1)
        
        try:
            shutil.copyfile("salt.bin", os.path.join(backup_dir, "salt.bin"))
            shutil.copyfile("vault.enc", os.path.join(backup_dir, "vault.enc"))
        except PermissionError:
            messagebox.showerror("USB Backup", "Cannot copy files - they may be in use by the application. Please close any other instances of LPM and try again.")
            return
        except OSError as e:
            if "Resource busy" in str(e) or "Device or resource busy" in str(e):
                messagebox.showerror("USB Backup", "Cannot copy files - they may be in use by the application. Please close any other instances of LPM and try again.")
                return
            else:
                raise
                
        messagebox.showinfo("USB Backup", f"Backup successful to:\n{backup_dir}")
    except Exception as e:
        print(f"Backup error: {e}")
        messagebox.showerror("USB Backup", f"Backup failed:\n{e}")


def set_window_icon(window):
    """Set the icon for a window."""
    try:
        icon = PhotoImage(file="lpm_icon.png")
        window.iconphoto(True, icon)
    except Exception:
        pass  # Continue if icon file not found


def open_settings_window(root):
    settings = tk.Toplevel(root)
    settings.title("Settings")
    settings.geometry("350x250")
    settings.resizable(False, False)
    center_window(settings, 350, 250)

    # Set rounded icon
    set_window_icon(settings)

    tk.Label(settings, text="Settings", font=("Arial", 14, "bold")).pack(pady=10)

    backup_btn = tk.Button(settings, text="Backup", command=open_backup_folder)
    backup_btn.pack(pady=10)
    usb_backup_btn = tk.Button(settings, text="USB Backup", command=usb_backup)
    usb_backup_btn.pack(pady=10)
    
    # Placeholder for future UI settings
    tk.Label(settings, text="UI Settings (coming soon)").pack(pady=10)

    settings.grab_set()


def main() -> None:
    ensure_gui()
    
    # Show startup screen first
    show_startup_screen()
    
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
    root.geometry("500x320")
    center_window(root, 500, 320)

    # Set rounded icon
    set_window_icon(root)

    listbox = tk.Listbox(root, width=40)
    listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    for service in vault:
        listbox.insert(tk.END, service)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5, fill=tk.X)
    for i in range(3):
        button_frame.grid_columnconfigure(i, weight=1)
    tk.Button(button_frame, text="Add", width=10, command=lambda: add_entry(vault, listbox)).grid(row=0, column=0, padx=3, sticky='ew')
    tk.Button(button_frame, text="Copy", width=10, command=lambda: copy_password(vault, listbox)).grid(row=0, column=1, padx=3, sticky='ew')
    tk.Button(button_frame, text="Delete", width=10, command=lambda: delete_entry(vault, listbox)).grid(row=0, column=2, padx=3, sticky='ew')

    # Settings button at the bottom, always visible
    settings_frame = tk.Frame(root)
    settings_frame.pack(side="bottom", fill="x")
    settings_btn = tk.Button(settings_frame, text="Settings", command=lambda: open_settings_window(root))
    settings_btn.pack(pady=10)

    def on_close():
        save_vault(fernet, vault)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
