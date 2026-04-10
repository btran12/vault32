"""
VaultLock crypto core: key derivation, lock, and unlock operations.
"""

import io
import json
import os
import secrets
import shutil
import struct
import tarfile
import tempfile
import time
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
MAGIC_V4 = b"VAULTLOCK\x04"
STREAM_CHUNK_SIZE = 64 * 1024 * 1024
INACTIVITY_LOCK_SECONDS = 5 * 60
SECURITY_PROFILES = {
    "ultra": 75_000,
    "fast": 150_000,
    "balanced": 250_000,
    "high": 600_000,
}
SECURITY_LABELS = {
    "ultra": "Ultra",
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


def _safe_target_path(base_dir: str, rel_path: str) -> str:
    target = os.path.normpath(os.path.join(base_dir, rel_path))
    if os.path.commonpath([target, base_dir]) != base_dir:
        raise ValueError("Corrupted archive path.")
    return target


def _build_manifest(folder_path: str):
    folder_path = os.path.normpath(folder_path)
    parent_dir = os.path.dirname(folder_path)
    root_arc = os.path.relpath(folder_path, parent_dir).replace("\\", "/")
    entries = []

    # Include root directory entry.
    try:
        st = os.stat(folder_path)
        mode = st.st_mode & 0o777
        mtime = int(st.st_mtime)
    except OSError:
        mode = 0o755
        mtime = int(time.time())
    entries.append({"type": "dir", "path": root_arc, "mode": mode, "mtime": mtime})

    total_file_bytes = 0
    file_count = 0
    for root, dirs, files in os.walk(folder_path):
        dirs.sort()
        files.sort()

        for dir_name in dirs:
            abs_dir = os.path.join(root, dir_name)
            rel = os.path.relpath(abs_dir, parent_dir).replace("\\", "/")
            try:
                st = os.stat(abs_dir)
                mode = st.st_mode & 0o777
                mtime = int(st.st_mtime)
            except OSError:
                mode = 0o755
                mtime = int(time.time())
            entries.append({"type": "dir", "path": rel, "mode": mode, "mtime": mtime})

        for file_name in files:
            abs_file = os.path.join(root, file_name)
            rel = os.path.relpath(abs_file, parent_dir).replace("\\", "/")
            st = os.stat(abs_file)
            size = int(st.st_size)
            total_file_bytes += size
            file_count += 1
            entries.append(
                {
                    "type": "file",
                    "path": rel,
                    "size": size,
                    "mode": st.st_mode & 0o777,
                    "mtime": int(st.st_mtime),
                }
            )

    manifest = {
        "version": 4,
        "chunk_size": STREAM_CHUNK_SIZE,
        "entries": entries,
    }
    return manifest, total_file_bytes, file_count


def _read_encrypted_chunk(in_file, aesgcm: AESGCM) -> tuple[bytes, int]:
    nonce = in_file.read(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError("Corrupted VaultLock file.")

    ct_len_buf = in_file.read(4)
    if len(ct_len_buf) != 4:
        raise ValueError("Corrupted VaultLock file.")

    ct_len = struct.unpack(">I", ct_len_buf)[0]
    ciphertext = in_file.read(ct_len)
    if len(ciphertext) != ct_len:
        raise ValueError("Corrupted VaultLock file.")

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file.")
    return plaintext, NONCE_LEN + 4 + ct_len


def lock_folder(folder_path: str, password: str, progress_cb=None, kdf_iterations: int = ITER_COUNT) -> str:
    """Encrypt folder using v4 manifest + per-file chunk stream to .locked file."""
    folder_path = os.path.normpath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError("Not a valid folder.")

    manifest, total_file_bytes, file_count = _build_manifest(folder_path)
    parent_dir = os.path.dirname(folder_path)

    if progress_cb:
        progress_cb(8)

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt, kdf_iterations)
    locked_path = folder_path + ".locked"

    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    manifest_nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(key)
    manifest_ciphertext = aesgcm.encrypt(manifest_nonce, manifest_bytes, None)

    with open(locked_path, "wb") as lf:
        lf.write(MAGIC_V4)
        lf.write(salt)
        lf.write(manifest_nonce)
        lf.write(struct.pack(">I", len(manifest_ciphertext)))
        lf.write(manifest_ciphertext)

        written_files = 0
        written_bytes = 0
        for entry in manifest["entries"]:
            if entry.get("type") != "file":
                continue

            abs_file = os.path.join(parent_dir, entry["path"])
            remaining = int(entry["size"])
            with open(abs_file, "rb") as rf:
                while remaining > 0:
                    chunk = rf.read(min(STREAM_CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("Source file changed during lock.")
                    nonce = secrets.token_bytes(NONCE_LEN)
                    ciphertext = aesgcm.encrypt(nonce, chunk, None)
                    lf.write(nonce)
                    lf.write(struct.pack(">I", len(ciphertext)))
                    lf.write(ciphertext)
                    remaining -= len(chunk)
                    written_bytes += len(chunk)

                    if progress_cb and total_file_bytes > 0:
                        progress_cb(10 + int((written_bytes / total_file_bytes) * 88))

            written_files += 1

        if file_count != written_files:
            raise ValueError("Locking failed: manifest mismatch.")

    if progress_cb:
        progress_cb(100)
    return locked_path


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
            candidate_iterations = kdf_iterations_list or [75_000, ITER_COUNT, 250_000, 600_000]
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

        if magic == MAGIC_V4:
            if progress_cb:
                progress_cb(20)

            salt = lf.read(SALT_LEN)
            manifest_nonce = lf.read(NONCE_LEN)
            manifest_len_buf = lf.read(4)
            if len(salt) != SALT_LEN or len(manifest_nonce) != NONCE_LEN or len(manifest_len_buf) != 4:
                raise ValueError("Corrupted VaultLock file.")

            manifest_len = struct.unpack(">I", manifest_len_buf)[0]
            manifest_ciphertext = lf.read(manifest_len)
            if len(manifest_ciphertext) != manifest_len:
                raise ValueError("Corrupted VaultLock file.")

            candidates = kdf_iterations_list or [75_000, ITER_COUNT, 250_000, 600_000]
            manifest = None
            active_key = None
            for iters in dict.fromkeys(candidates):
                try:
                    key = derive_key(password, salt, iters)
                    aesgcm = AESGCM(key)
                    manifest_plain = aesgcm.decrypt(manifest_nonce, manifest_ciphertext, None)
                    manifest = json.loads(manifest_plain.decode("utf-8"))
                    active_key = key
                    break
                except Exception:
                    manifest = None
                    active_key = None

            if manifest is None or active_key is None:
                raise ValueError("Wrong password or corrupted file.")

            entries = manifest.get("entries", [])
            chunk_size = int(manifest.get("chunk_size", STREAM_CHUNK_SIZE))
            if not isinstance(entries, list) or chunk_size <= 0:
                raise ValueError("Corrupted VaultLock file.")

            if progress_cb:
                progress_cb(35)

            os.makedirs(out_dir, exist_ok=True)
            temp_extract = tempfile.mkdtemp(prefix="vaultlock_out_", dir=out_dir)
            processed = magic_len + SALT_LEN + NONCE_LEN + 4 + manifest_len
            aesgcm = AESGCM(active_key)
            try:
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError("Corrupted VaultLock file.")
                    rel = entry.get("path")
                    typ = entry.get("type")
                    if not isinstance(rel, str) or not rel:
                        raise ValueError("Corrupted VaultLock file.")

                    target = _safe_target_path(temp_extract, rel)

                    if typ == "dir":
                        os.makedirs(target, exist_ok=True)
                        continue

                    if typ != "file":
                        continue

                    size = int(entry.get("size", -1))
                    if size < 0:
                        raise ValueError("Corrupted VaultLock file.")

                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    remaining = size
                    with open(target, "wb") as wf:
                        while remaining > 0:
                            plaintext, consumed = _read_encrypted_chunk(lf, aesgcm)
                            expected = min(chunk_size, remaining)
                            if len(plaintext) != expected:
                                raise ValueError("Corrupted VaultLock file.")
                            wf.write(plaintext)
                            remaining -= len(plaintext)
                            processed += consumed
                            if progress_cb and total_size > 0:
                                progress_cb(35 + int((processed / total_size) * 60))

                    mtime = entry.get("mtime")
                    if isinstance(mtime, (int, float)):
                        try:
                            os.utime(target, (mtime, mtime))
                        except Exception:
                            pass

                # Ensure no unexpected encrypted payload remains.
                if lf.read(1) not in (b"",):
                    raise ValueError("Corrupted VaultLock file.")

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

        if magic == MAGIC_V3:
            if progress_cb:
                progress_cb(20)

            salt = lf.read(SALT_LEN)
            chunk_size_buf = lf.read(4)
            if len(salt) != SALT_LEN or len(chunk_size_buf) != 4:
                raise ValueError("Corrupted VaultLock file.")

            _chunk_size = struct.unpack(">I", chunk_size_buf)[0]
            candidates = kdf_iterations_list or [75_000, ITER_COUNT, 250_000, 600_000]
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
            candidate_iterations = kdf_iterations_list or [75_000, ITER_COUNT, 250_000, 600_000]
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
