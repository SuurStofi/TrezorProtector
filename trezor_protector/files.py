"""
File encryption / decryption.

Encrypted file wire format
--------------------------
  6 bytes  magic    "TPENC1"
  2 bytes  meta_len  big-endian uint16 — length of the original filename
  N bytes  meta      original filename (UTF-8)
  rest     AES-256-GCM blob (12-byte nonce + ciphertext + 16-byte tag)

The original filename is stored inside the encrypted blob so it survives
renames of the .tpenc file.
"""

from __future__ import annotations

from pathlib import Path

from .crypto import encrypt, decrypt

_MAGIC = b"TPENC1"
_ENCRYPTED_EXT = ".tpenc"


# ------------------------------------------------------------------
# Encrypt
# ------------------------------------------------------------------

def encrypt_file(
    key: bytes,
    src: Path,
    dst: Path | None = None,
) -> Path:
    """
    Encrypt *src* and write the result to *dst*.

    If *dst* is None it defaults to src + ".tpenc".
    Returns the path of the encrypted file.
    """
    if dst is None:
        dst = src.with_name(src.name + _ENCRYPTED_EXT)

    plaintext = src.read_bytes()
    meta = src.name.encode("utf-8")
    meta_len = len(meta).to_bytes(2, "big")

    payload = meta_len + meta + plaintext
    blob = encrypt(key, payload)

    dst.write_bytes(_MAGIC + blob)
    return dst


# ------------------------------------------------------------------
# Decrypt
# ------------------------------------------------------------------

def decrypt_file(
    key: bytes,
    src: Path,
    dst: Path | None = None,
) -> tuple[Path, str]:
    """
    Decrypt *src* and write plaintext to *dst*.

    If *dst* is None the output path is derived from the original filename
    embedded in the encrypted file; it lands in the same directory as *src*.
    Returns (output_path, original_filename).
    """
    raw = src.read_bytes()
    _check_magic(raw)

    blob = raw[len(_MAGIC):]
    payload = decrypt(key, blob)

    original_name, plaintext = _split_payload(payload)

    if dst is None:
        # Use only the basename: a crafted file must not be able to steer
        # the output outside src's directory (path traversal).
        dst = src.parent / Path(original_name.replace("\\", "/")).name

    dst.write_bytes(plaintext)
    return dst, original_name


def read_encrypted(key: bytes, src: Path) -> tuple[bytes, str]:
    """
    Decrypt *src* and return (plaintext_bytes, original_filename)
    without writing anything to disk.
    """
    raw = src.read_bytes()
    _check_magic(raw)

    blob = raw[len(_MAGIC):]
    payload = decrypt(key, blob)
    original_name, plaintext = _split_payload(payload)
    return plaintext, original_name


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _check_magic(raw: bytes) -> None:
    if not raw.startswith(_MAGIC):
        raise ValueError(
            "File does not start with the TrezorProtector magic header.\n"
            "It may not be a .tpenc file, or it may be corrupted."
        )


def _split_payload(payload: bytes) -> tuple[str, bytes]:
    meta_len = int.from_bytes(payload[:2], "big")
    original_name = payload[2 : 2 + meta_len].decode("utf-8")
    plaintext = payload[2 + meta_len :]
    return original_name, plaintext
