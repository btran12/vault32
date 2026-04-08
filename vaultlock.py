#!/usr/bin/env python3
"""
vault32 launcher.
"""

import sys

from vl_gui import run_app


if __name__ == "__main__":
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        import subprocess

        print("Installing required package: cryptography")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])

    try:
        from PySide6.QtWidgets import QApplication  # noqa: F401
    except ImportError:
        import subprocess

        print("Installing required package: PySide6")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PySide6"])

    raise SystemExit(run_app())
