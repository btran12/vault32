# vault32

vault32 is a desktop app for locking and unlocking folders with password-based encryption.

It provides:
- A private vault workflow in the app UI
- Manual tools to lock any folder and unlock any `.locked` file
- Windows packaging to a standalone `.exe` using PyInstaller

## Project Structure

- `vaultlock.py` - app launcher/entrypoint
- `vl_gui.py` - PySide6 GUI and user workflows
- `vl_crypto.py` - encryption/decryption core
- `build.ps1` - build helper script for packaging
- `vault32.spec` - reusable PyInstaller spec
- `assets/vault32.ico` - application icon used by EXE builds

## Requirements

- Windows
- Python 3.10+ recommended
- Python packages: `cryptography`, `PySide6`

Install dependencies:

```powershell
py -m pip install --upgrade pip setuptools wheel
py -m pip install cryptography pyside6
```

## Run From Source

```powershell
py .\vaultlock.py
```

## How To Use

### Private Vault Mode

1. Launch the app.
2. On first run, set a private vault password.
3. Add files/folders to your private vault.
4. Lock and unlock the vault from the app.

### Tool Mode (Manual Operations)

- **Tool: Lock Folder**
  1. Pick a folder.
  2. Enter and confirm password.
  3. Encrypt to create a `.locked` file.

- **Tool: Unlock File**
  1. Pick a `.locked` file.
  2. Pick restore destination.
  3. Enter password to decrypt.

## Package As EXE

You can package without manually typing long PyInstaller commands.

### Option A: Use build script (recommended)

From project root:

```powershell
.\build.ps1 -InstallDeps -Mode spec
```

Build modes:

- `spec` (default):
  ```powershell
  .\build.ps1 -Mode spec
  ```
  Output: `.\dist\vault32\vault32.exe`

- `onedir`:
  ```powershell
  .\build.ps1 -Mode onedir
  ```
  Output: `.\dist\vault32\vault32.exe`

- `onefile`:
  ```powershell
  .\build.ps1 -Mode onefile
  ```
  Output: `.\dist\vault32.exe`

### Option B: Build directly with PyInstaller

```powershell
py -m pip install pyinstaller cryptography pyside6
py -m PyInstaller --noconfirm --clean --windowed --name vault32 --collect-all cryptography vaultlock.py
```

## Distribution Notes

- The packaged EXE does **not** require Python to be installed on target machines.
- `onedir` starts faster and is easier to debug.
- `onefile` is easier to share but may start a bit slower.
- Test on a clean machine/VM before sharing.

## Troubleshooting

- If build fails due to missing modules, reinstall dependencies:
  ```powershell
  py -m pip install --upgrade pip setuptools wheel pyinstaller cryptography pyside6
  ```
- If Windows Defender flags a fresh EXE, rebuild and sign if needed for distribution in managed environments.
