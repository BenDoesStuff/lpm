# LPM - Local Password Manager

A secure, encrypted local password manager with a modern GUI built in Python. LPM provides a simple yet powerful way to store and manage your passwords locally with strong encryption.

![LPM Logo](lpm_icon.png)

## ✨ Features

### 🔐 Security
- **AES-256 encryption** using Fernet (cryptography library)
- **PBKDF2 key derivation** with 390,000 iterations
- **Salt-based encryption** for enhanced security
- **Local storage only** - your data never leaves your device
- **Master password protection** for all stored credentials

### 🎨 User Interface
- **Modern GUI** built with Tkinter
- **Custom LPM branding** with keyhole design
- **Centered windows** for professional appearance
- **Show/Hide password** toggles on all password fields
- **Responsive design** that adapts to window resizing
- **System theme detection** (macOS dark mode support)

### 💾 Backup & Recovery
- **Local backup** - open folder containing encrypted files
- **USB backup** - automatically detect and backup to USB drives
- **Cross-platform** backup support (macOS, Windows, Linux)
- **Automatic folder creation** (`LPM_BACKUP` directory)

### 🔧 Functionality
- **Password generation** with customizable length
- **Service-based organization** for easy password lookup
- **One-click password copying** to clipboard
- **Add/Delete/Edit** password entries
- **Startup screen** with branding
- **Settings panel** for configuration

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Graphical desktop environment (for GUI)

### Quick Start
1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/lpm.git
   cd lpm
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run LPM**
   ```bash
   python password_manager.py
   ```

## 📖 Usage

### First Run
1. Launch LPM - you'll see the startup screen
2. Create your **master password** (required for encryption)
3. Use the **Generate** button for a strong random password
4. Confirm your master password

### Daily Use
1. **Enter your master password** to unlock the vault
2. **Add new entries** using the "Add" button
3. **Copy passwords** with one click
4. **Delete entries** when no longer needed
5. **Access settings** for backup options

### Backup Your Data
- **Local Backup**: Click Settings → Backup to open the folder containing your encrypted files
- **USB Backup**: Click Settings → USB Backup to copy files to a connected USB drive

## 🛠️ Building

### macOS
```bash
# Install PyInstaller
pip install pyinstaller

# Build macOS app
pyinstaller --onedir --windowed --name LPM password_manager.py

# Optional: Add custom icon (convert PNG to ICNS first)
pyinstaller --onedir --windowed --name LPM --icon=lpm_icon.icns password_manager.py
```

### Windows
```bash
# Install PyInstaller
pip install pyinstaller

# Build Windows executable
pyinstaller --onefile --windowed --name LPM.exe --icon=lpm_icon.png password_manager.py
```

### Linux
```bash
# Install PyInstaller
pip install pyinstaller

# Build Linux executable
pyinstaller --onefile --windowed --name LPM password_manager.py
```

## 📁 File Structure

```
lpm/
├── password_manager.py    # Main application
├── requirements.txt       # Python dependencies
├── lpm_icon.png          # Application icon
├── README.md             # This file
├── vault.enc             # Encrypted password data (created after first use)
└── salt.bin              # Encryption salt (created after first use)
```

## 🔒 Security Details

### Encryption
- **Algorithm**: AES-256 via Fernet
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 390,000 (OWASP recommended)
- **Salt**: 16-byte random salt per installation

### Data Storage
- **vault.enc**: Encrypted JSON containing all passwords
- **salt.bin**: Random salt for key derivation
- **No plaintext storage** of passwords anywhere

### Security Best Practices
- Passwords are never stored in plaintext
- Master password is never stored (only used for key derivation)
- All encryption/decryption happens in memory
- Automatic cleanup of sensitive data

## 🖥️ System Requirements

- **OS**: macOS 10.14+, Windows 10+, or Linux with GUI
- **Python**: 3.8 or higher
- **Memory**: 50MB RAM minimum
- **Storage**: 10MB disk space
- **Display**: 1024x768 minimum resolution

## 🐛 Troubleshooting

### Common Issues

**"No module named 'cryptography'"**
```bash
pip install cryptography
```

**"Tkinter could not open a window"**
- Ensure you have a graphical environment
- On Linux: `sudo apt-get install python3-tk`

**USB Backup not working**
- Ensure USB drive is properly mounted
- Check file permissions
- Try running as administrator (Windows)

**Icon not displaying**
- Ensure `lpm_icon.png` is in the same directory
- For macOS builds, convert PNG to ICNS format

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

LPM is designed for personal use and local password management. While it uses strong encryption, no security system is perfect. Always:
- Use strong, unique master passwords
- Keep your backup files secure
- Regularly update your passwords
- Consider additional security measures for highly sensitive data

## 🆘 Support

If you encounter any issues or have questions:
1. Check the [Issues](https://github.com/yourusername/lpm/issues) page
2. Create a new issue with detailed information
3. Include your operating system and Python version

---

**Made with ❤️ for secure password management**