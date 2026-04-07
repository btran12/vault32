"""
VaultLock crypto core: key derivation, lock, and unlock operations.
"""

import io
import os
import secrets
import shutil
import struct
import tarfile
import tempfile
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_LEN = 32
NONCE_LEN = 12
ITER_COUNT = 150_000
KEY_LEN = 32
MAGIC_V1 = b"VAULTLOCK\x01"
MAGIC_V2 = b"VAULTLOCK\x02"
MAGIC_V3 = b"VAULTLOCK\x03"
STREAM_CHUNK_SIZE = 32 * 1024 * 1024
INACTIVITY_LOCK_SECONDS = 5 * 60
SECURITY_PROFILES = {
    "fast": 150_000,
    "balanced": 250_000,
    "high": 600_000,
}
SECURITY_LABELS = {
    "fast": "Fast",
    "balanced": "Balanced",
    "high": "High",
}

# Extensions that are usually already compressed and expensive to recompress.
FAST_STORE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
    ".mp4", ".mov", ".mkv", ".avi", ".wmv", ".mp3", ".m4a", ".flac",
    ".pdf", ".docx", ".xlsx", ".pptx", ".iso",
}


def choose_zip_strategy(file_path: str):
    """Return (compress_type, compress_level_or_none) tuned for maximum speed."""
    # For maximum lock/unlock throughput, avoid compression entirely.
    return zipfile.ZIP_STORED, None


def derive_key(password: str, salt: bytes, iterations: int = ITER_COUNT) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


class _EncryptedChunkWriter:
    """Write plaintext bytes and emit chunked AES-GCM encrypted records."""

    def __init__(self, out_file, key: bytes, chunk_size: int):
        self._out_file = out_file
        self._aesgcm = AESGCM(key)
        self._chunk_size = chunk_size
        self._buf = bytearray()

    def _flush_one(self, data: bytes):
        nonce = secrets.token_bytes(NONCE_LEN)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        self._out_file.write(nonce)
        self._out_file.write(struct.pack(">I", len(ciphertext)))
        self._out_file.write(ciphertext)

    def write(self, b):
        if not b:
            return 0
        self._buf.extend(b)
        while len(self._buf) >= self._chunk_size:
            chunk = bytes(self._buf[:self._chunk_size])
            del self._buf[:self._chunk_size]
            self._flush_one(chunk)
        return len(b)

    def flush(self):
        return

    def close(self):
        if self._buf:
            self._flush_one(bytes(self._buf))
            self._buf.clear()


class _DecryptedChunkReader:
    """Read chunked AES-GCM encrypted records as a plaintext stream."""

    def __init__(self, in_file, key: bytes):
        self._in_file = in_file
        self._aesgcm = AESGCM(key)
        self._buf = bytearray()
        self._eof = False

    def _fill_once(self):
        nonce = self._in_file.read(NONCE_LEN)
        if nonce == b"":
            self._eof = True
            return
        if len(nonce) != NONCE_LEN:
            raise ValueError("Corrupted VaultLock file.")

        ct_len_buf = self._in_file.read(4)
        if len(ct_len_buf) != 4:
            raise ValueError("Corrupted VaultLock file.")
        ct_len = struct.unpack(">I", ct_len_buf)[0]

        ciphertext = self._in_file.read(ct_len)
        if len(ciphertext) != ct_len:
            raise ValueError("Corrupted VaultLock file.")

        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Wrong password or corrupted file.")
        self._buf.extend(plaintext)

    def read(self, size=-1):
        if size is None or size < 0:
            while not self._eof:
                self._fill_once()
            out = bytes(self._buf)
            self._buf.clear()
            return out

        while len(self._buf) < size and not self._eof:
            self._fill_once()

        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out


class _ProgressFileReader:
    def __init__(self, file_obj, on_bytes):
        self._f = file_obj
        self._on_bytes = on_bytes

    def read(self, size=-1):
        data = self._f.read(size)
        if data:
            self._on_bytes(len(data))
        return data


def lock_folder(folder_path: str, password: str, progress_cb=None, kdf_iterations: int = ITER_COUNT) -> str:
    """Zip folder on disk -> chunked AES-256-GCM encrypt (v2) to .locked file."""
    folder_path = os.path.normpath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError("Not a valid folder.")

    # Collect files
    all_files = []
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            all_files.append(os.path.join(root, file_name))

    total = len(all_files)

    fd, temp_zip = tempfile.mkstemp(prefix="vaultlock_", suffix=".zip")
    os.close(fd)

    try:
        with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            if total == 0:
                zf.writestr(os.path.basename(folder_path) + "/", "")
                if progress_cb:
                    progress_cb(70)
            else:
                for i, filepath in enumerate(all_files):
                    arcname = os.path.relpath(filepath, os.path.dirname(folder_path))
                    compress_type, compress_level = choose_zip_strategy(filepath)
                    if compress_level is None:
                        zf.write(filepath, arcname, compress_type=compress_type)
                    else:
                        zf.write(filepath, arcname, compress_type=compress_type, compresslevel=compress_level)
                    if progress_cb:
                        progress_cb(int((i + 1) / total * 70))

        if progress_cb:
            progress_cb(75)
        salt = secrets.token_bytes(SALT_LEN)
        key = derive_key(password, salt, kdf_iterations)

        if progress_cb:
            progress_cb(85)
        aesgcm = AESGCM(key)
        locked_path = folder_path + ".locked"
        zip_size = os.path.getsize(temp_zip)
        processed = 0

        with open(temp_zip, "rb") as rf, open(locked_path, "wb") as lf:
            lf.write(MAGIC_V2)
            lf.write(salt)
            lf.write(struct.pack(">I", STREAM_CHUNK_SIZE))

            while True:
                chunk = rf.read(STREAM_CHUNK_SIZE)
                if not chunk:
                    break

                nonce = secrets.token_bytes(NONCE_LEN)
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                lf.write(nonce)
                lf.write(struct.pack(">I", len(ciphertext)))
                lf.write(ciphertext)

                processed += len(chunk)
                if progress_cb and zip_size > 0:
                    progress_cb(85 + int((processed / zip_size) * 15))

        if progress_cb:
            progress_cb(100)
        return locked_path
    finally:
        try:
            os.remove(temp_zip)
        except OSError:
            pass


def unlock_file(locked_path: str, password: str, out_dir: str, progress_cb=None, kdf_iterations_list=None) -> str:
    """Decrypt .locked file -> restore original folder structure."""
    if not os.path.isfile(locked_path):
        raise ValueError("File not found.")

    magic_len = len(MAGIC_V1)
    total_size = os.path.getsize(locked_path)

    with open(locked_path, "rb") as lf:
        magic = lf.read(magic_len)

        if magic == MAGIC_V1:
            if progress_cb:
                progress_cb(20)

            salt = lf.read(SALT_LEN)
            nonce = lf.read(NONCE_LEN)
            ciphertext = lf.read()
            candidate_iterations = kdf_iterations_list or [ITER_COUNT, 250_000, 600_000]
            if progress_cb:
                progress_cb(60)

            plaintext = None
            for iters in dict.fromkeys(candidate_iterations):
                try:
                    key = derive_key(password, salt, iters)
                    aesgcm = AESGCM(key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    break
                except Exception:
                    plaintext = None

            if plaintext is None:
                raise ValueError("Wrong password or corrupted file.")

            if progress_cb:
                progress_cb(80)

            buf = io.BytesIO(plaintext)
            with zipfile.ZipFile(buf, "r") as zf:
                zf.extractall(out_dir)

            if progress_cb:
                progress_cb(100)
            return out_dir

        if magic == MAGIC_V3:
            if progress_cb:
                progress_cb(20)

            salt = lf.read(SALT_LEN)
            chunk_size_buf = lf.read(4)
            if len(salt) != SALT_LEN or len(chunk_size_buf) != 4:
                raise ValueError("Corrupted VaultLock file.")

            _chunk_size = struct.unpack(">I", chunk_size_buf)[0]
            candidates = kdf_iterations_list or [ITER_COUNT, 250_000, 600_000]
            success = False

            # Extract to a temp directory first; move into destination only on success.
            os.makedirs(out_dir, exist_ok=True)
            temp_extract = tempfile.mkdtemp(prefix="vaultlock_out_", dir=out_dir)
            try:
                for iters in dict.fromkeys(candidates):
                    # Clean temp dir between attempts.
                    for name in os.listdir(temp_extract):
                        path = os.path.join(temp_extract, name)
                        if os.path.isdir(path):
                            shutil.rmtree(path, ignore_errors=True)
                        else:
                            try:
                                os.remove(path)
                            except OSError:
                                pass

                    lf.seek(magic_len + SALT_LEN + 4)
                    try:
                        key = derive_key(password, salt, iters)
                        dec_reader = _DecryptedChunkReader(lf, key)
                        with tarfile.open(fileobj=dec_reader, mode="r|*") as tf:
                            for member in tf:
                                target = os.path.normpath(os.path.join(temp_extract, member.name))
                                if os.path.commonpath([target, temp_extract]) != temp_extract:
                                    raise ValueError("Corrupted archive path.")

                                if member.isdir():
                                    os.makedirs(target, exist_ok=True)
                                    continue

                                if not member.isfile():
                                    # Skip links/special files for safety.
                                    continue

                                os.makedirs(os.path.dirname(target), exist_ok=True)
                                src = tf.extractfile(member)
                                if src is None:
                                    continue
                                with src, open(target, "wb") as wf:
                                    shutil.copyfileobj(src, wf, length=1024 * 1024)

                                try:
                                    os.utime(target, (member.mtime, member.mtime))
                                except Exception:
                                    pass

                        success = True
                        break
                    except Exception:
                        success = False

                if not success:
                    raise ValueError("Wrong password or corrupted file.")

                # Move extracted content to destination.
                for name in os.listdir(temp_extract):
                    src = os.path.join(temp_extract, name)
                    dst = os.path.join(out_dir, name)
                    if os.path.exists(dst):
                        if os.path.isdir(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        else:
                            try:
                                os.remove(dst)
                            except OSError:
                                pass
                    shutil.move(src, dst)

                if progress_cb:
                    progress_cb(100)
                return out_dir
            finally:
                shutil.rmtree(temp_extract, ignore_errors=True)

        if magic != MAGIC_V2:
            raise ValueError("Not a valid VaultLock file.")

        if progress_cb:
            progress_cb(20)

        salt = lf.read(SALT_LEN)
        chunk_size_buf = lf.read(4)
        if len(salt) != SALT_LEN or len(chunk_size_buf) != 4:
            raise ValueError("Corrupted VaultLock file.")

        _chunk_size = struct.unpack(">I", chunk_size_buf)[0]
        if progress_cb:
            progress_cb(35)

        fd, temp_zip = tempfile.mkstemp(prefix="vaultlock_dec_", suffix=".zip")
        os.close(fd)

        try:
            candidate_iterations = kdf_iterations_list or [ITER_COUNT, 250_000, 600_000]
            success = False
            for iters in dict.fromkeys(candidate_iterations):
                lf.seek(magic_len + SALT_LEN + 4)
                processed = magic_len + SALT_LEN + 4
                try:
                    key = derive_key(password, salt, iters)
                    aesgcm = AESGCM(key)
                    with open(temp_zip, "wb") as wf:
                        while True:
                            nonce = lf.read(NONCE_LEN)
                            if nonce == b"":
                                break
                            if len(nonce) != NONCE_LEN:
                                raise ValueError("Corrupted VaultLock file.")

                            ct_len_buf = lf.read(4)
                            if len(ct_len_buf) != 4:
                                raise ValueError("Corrupted VaultLock file.")

                            ct_len = struct.unpack(">I", ct_len_buf)[0]
                            ciphertext = lf.read(ct_len)
                            if len(ciphertext) != ct_len:
                                raise ValueError("Corrupted VaultLock file.")

                            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                            wf.write(plaintext)

                            processed += NONCE_LEN + 4 + ct_len
                            if progress_cb and total_size > 0:
                                progress_cb(35 + int((processed / total_size) * 55))
                    success = True
                    break
                except Exception:
                    success = False

            if not success:
                raise ValueError("Wrong password or corrupted file.")

            if progress_cb:
                progress_cb(92)

            with zipfile.ZipFile(temp_zip, "r") as zf:
                zf.extractall(out_dir)

            if progress_cb:
                progress_cb(100)
            return out_dir
        finally:
            try:
                os.remove(temp_zip)
            except OSError:
                pass
