"""
AES-256-GCM authenticated encryption.

Every encrypt call produces a unique random nonce, so encrypting the same
plaintext twice yields different ciphertexts. The GCM tag ensures any
tampering is detected on decrypt.

Wire format:  12-byte nonce | ciphertext | 16-byte GCM tag
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. key must be exactly 32 bytes."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt. data must be nonce + ciphertext + tag."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(data) < _NONCE_LEN + 16:
        raise ValueError("Data too short to be valid ciphertext")
    nonce, ciphertext = data[:_NONCE_LEN], data[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)
