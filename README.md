# LPM

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
Both the master password setup and the "Add Entry" dialog include a "Generate"
button that creates a strong random password for convenience.

## Packaging as a single executable

Install PyInstaller and create an executable:

```bash
pip install pyinstaller
pyinstaller --onefile --name LPM password_manager.py
```

The executable will be placed in the `dist` directory. Run the command on
Windows to generate `LPM.exe`, and on macOS to generate `LPM`.

### Creating a macOS installer

After building the single-file executable on a Mac, you can package it into a
disk image (`.dmg`) so users can drag it to their Applications folder:

```bash
# run on macOS
pyinstaller --onefile --name LPM password_manager.py
cd dist
hdiutil create -volname LPM -srcfolder . -ov -format UDZO ../LPM.dmg
```

