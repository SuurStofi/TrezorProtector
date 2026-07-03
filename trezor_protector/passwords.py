"""
Helpers for packing/unpacking the JSON blob stored inside each password entry.

Schema stored (encrypted):
  {
    "password": "<plaintext password>",
    "notes":    "<optional free-form text>"
  }
"""

import json
import secrets
import string


def pack(password: str, notes: str = "") -> bytes:
    return json.dumps({"password": password, "notes": notes}, ensure_ascii=False).encode()


def unpack(data: bytes) -> dict:
    return json.loads(data.decode())


def generate_password(
    length: int = 20,
    *,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a cryptographically strong random password."""
    alphabet = string.ascii_lowercase
    mandatory: list[str] = []

    if upper:
        alphabet += string.ascii_uppercase
        mandatory.append(secrets.choice(string.ascii_uppercase))
    if digits:
        alphabet += string.digits
        mandatory.append(secrets.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        alphabet += sym
        mandatory.append(secrets.choice(sym))

    remaining = length - len(mandatory)
    if remaining < 0:
        remaining = 0

    pw_chars = [secrets.choice(alphabet) for _ in range(remaining)] + mandatory

    # Shuffle so mandatory chars aren't always at the end
    for i in range(len(pw_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]

    return "".join(pw_chars)
