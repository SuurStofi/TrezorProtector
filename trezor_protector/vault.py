"""
JSON vault — the single file that lives on disk.

Layout:
  {
    "version": 1,
    "created_at": "<iso8601>",
    "encrypted_master_key": "<32-byte hex>",   # encrypted by Trezor
    "passwords": [
      {
        "id": "<uuid4>",
        "name": "github.com",
        "username": "alice@example.com",
        "url": "https://github.com",
        "encrypted_data": "<hex>",              # AES-256-GCM blob
        "created_at": "<iso8601>",
        "updated_at": "<iso8601>"
      }
    ]
  }

The encrypted_master_key can only be decrypted by the Trezor that created it.
The encrypted_data blobs can only be decrypted with the master key.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_VAULT_PATH = Path.home() / ".trezorprotector" / "vault.json"

_VERSION = 1


class Vault:
    def __init__(self, path: Path = DEFAULT_VAULT_PATH) -> None:
        self.path = Path(path)
        self._data: Optional[dict] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def create(self, encrypted_master_key: bytes) -> None:
        """Write a brand-new empty vault. Overwrites if present."""
        self._data = {
            "version": _VERSION,
            "created_at": _now(),
            "encrypted_master_key": encrypted_master_key.hex(),
            "passwords": [],
        }
        self._write()

    def load(self) -> None:
        if not self.exists:
            raise FileNotFoundError(
                f"No vault found at {self.path}.\n"
                "Run  python main.py init  to create one."
            )
        with open(self.path, "r", encoding="utf-8") as fh:
            self._data = json.load(fh)

    # ------------------------------------------------------------------
    # Master key
    # ------------------------------------------------------------------

    def get_encrypted_master_key(self) -> bytes:
        self._need()
        return bytes.fromhex(self._data["encrypted_master_key"])

    # ------------------------------------------------------------------
    # Password CRUD
    # ------------------------------------------------------------------

    def add_password(
        self,
        name: str,
        username: str,
        url: str,
        encrypted_data: bytes,
    ) -> str:
        self._need()
        entry_id = str(uuid.uuid4())
        self._data["passwords"].append(
            {
                "id": entry_id,
                "name": name,
                "username": username,
                "url": url,
                "encrypted_data": encrypted_data.hex(),
                "created_at": _now(),
                "updated_at": _now(),
            }
        )
        self._write()
        return entry_id

    def update_password(
        self,
        entry_id: str,
        *,
        name: Optional[str] = None,
        username: Optional[str] = None,
        url: Optional[str] = None,
        encrypted_data: Optional[bytes] = None,
    ) -> None:
        self._need()
        for entry in self._data["passwords"]:
            if entry["id"] == entry_id:
                if name is not None:
                    entry["name"] = name
                if username is not None:
                    entry["username"] = username
                if url is not None:
                    entry["url"] = url
                if encrypted_data is not None:
                    entry["encrypted_data"] = encrypted_data.hex()
                entry["updated_at"] = _now()
                self._write()
                return
        raise KeyError(f"Entry {entry_id!r} not found")

    def delete_password(self, entry_id: str) -> bool:
        self._need()
        before = len(self._data["passwords"])
        self._data["passwords"] = [
            p for p in self._data["passwords"] if p["id"] != entry_id
        ]
        if len(self._data["passwords"]) < before:
            self._write()
            return True
        return False

    def get_passwords(self) -> list:
        self._need()
        return list(self._data["passwords"])

    def find_passwords(self, query: str) -> list:
        self._need()
        q = query.lower()
        return [
            p for p in self._data["passwords"]
            if q in p["name"].lower()
            or q in p.get("username", "").lower()
            or q in p.get("url", "").lower()
        ]

    def get_password_by_id(self, entry_id: str) -> Optional[dict]:
        self._need()
        for p in self._data["passwords"]:
            if p["id"] == entry_id:
                return p
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write(self) -> None:
        """Atomic write: temp file + backup + rename, restrictive perms.

        A crash mid-write can no longer destroy the vault, and the previous
        version is kept as vault.json.bak.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        if self.path.exists():
            shutil.copy2(self.path, self.path.with_suffix(".json.bak"))
        os.replace(tmp, self.path)

    def _need(self) -> None:
        if self._data is None:
            raise RuntimeError("Vault not loaded. Call load() first.")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
