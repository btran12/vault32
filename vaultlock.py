#!/usr/bin/env python3
"""
vault32 launcher.
"""

import sys

from vl_gui import VaultLockApp


if __name__ == "__main__":
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        import subprocess

        print("Installing required package: cryptography")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])

    app = VaultLockApp()
    app.mainloop()
