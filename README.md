# lpm

Local Password Manager

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python password_manager.py
```

On first run, you'll be prompted to create a master password. This password will
be required each time you open the manager.

## Packaging as a single executable

Install PyInstaller and create an executable:

```bash
pip install pyinstaller
pyinstaller --onefile password_manager.py
```

The executable will be placed in the `dist` directory.
