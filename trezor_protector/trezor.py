"""
Trezor device interface — compatible with trezorlib 0.20+.

Key changes in 0.20.x vs 0.13.x:
  - TrezorClient is now abstract; concrete clients come from get_client()
  - PIN / button callbacks are passed to AppManifest, not a UI object
  - CipherKeyValue is misc.encrypt_keyvalue / decrypt_keyvalue, both take a Session
  - A Session is obtained from get_default_session(client) after the device is unlocked

Flow
----
1. connect(pin_callback, button_callback)
     → AppManifest + get_client() → TrezorClientV1 or TrezorClientThp
2. encrypt_master_key(raw_key)
     → get_default_session(client)  ← device PIN is entered here if needed
     → misc.encrypt_keyvalue(session, …)  ← device button confirmation here
3. decrypt_master_key(enc_key)
     → same pattern, decrypt_keyvalue
"""

from __future__ import annotations

from typing import Callable, Optional

_DERIV_PATH = "m/10016'/0'"
_APP_KEY    = "TrezorProtector"


class TrezorManager:
    """Wraps the trezorlib 0.20+ client with the operations we need."""

    def __init__(self) -> None:
        self._client = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(
        self,
        pin_callback:    Optional[Callable] = None,
        button_callback: Optional[Callable] = None,
    ) -> None:
        """
        Open the first available Trezor device.

        For CLI use, pass nothing — ClickUI provides terminal prompts.
        For GUI use, pass callables:
          pin_callback(req: messages.PinMatrixRequest) -> str
          button_callback(req: messages.ButtonRequest)  -> None
        """
        try:
            from trezorlib.client import AppManifest, get_client
            from trezorlib.transport import get_transport

            if pin_callback is None:
                from trezorlib.cli.ui import ClickUI
                _ui = ClickUI()
                pin_callback    = _ui.get_pin
                button_callback = _ui.button_request

            app = AppManifest(
                app_name="TrezorProtector",
                pin_callback=pin_callback,
                button_callback=button_callback,
            )
            transport = get_transport()
            self._client = get_client(app, transport)
        except Exception as exc:
            self._client = None
            raise ConnectionError(
                f"Cannot connect to Trezor: {exc}\n"
                "Make sure the device is plugged in and the Trezor Bridge\n"
                "(or HID/WebUSB drivers on Windows) is installed."
            ) from exc

    def disconnect(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ------------------------------------------------------------------
    # Device info
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        self._require()
        f = self._client.features
        model = getattr(f, "model", None) or "Trezor One"
        label = getattr(f, "label", None) or "(no label)"
        fw    = f"{f.major_version}.{f.minor_version}.{f.patch_version}"
        return {
            "model":       str(model),
            "label":       str(label),
            "firmware":    fw,
            "initialized": bool(f.initialized),
        }

    # ------------------------------------------------------------------
    # Key operations  (CipherKeyValue via trezorlib 0.20+ API)
    # ------------------------------------------------------------------

    def encrypt_master_key(self, raw_key: bytes) -> bytes:
        """
        Encrypt a 32-byte master key on the device.

        The device will display the app name and ask for button confirmation.
        Returns 32 bytes that are safe to persist on disk.
        """
        if len(raw_key) != 32:
            raise ValueError("raw_key must be exactly 32 bytes")
        self._require()
        return self._keyvalue(raw_key, encrypt=True)

    def decrypt_master_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt 32 bytes back to the original master key.

        Requires the same Trezor device (same seed) that originally encrypted it.
        """
        if len(encrypted_key) != 32:
            raise ValueError("encrypted_key must be exactly 32 bytes")
        self._require()
        return self._keyvalue(encrypted_key, encrypt=False)

    def _keyvalue(self, value: bytes, *, encrypt: bool) -> bytes:
        from trezorlib import tools
        from trezorlib.client import get_default_session
        from trezorlib.misc import decrypt_keyvalue, encrypt_keyvalue

        address_n = tools.parse_path(_DERIV_PATH)
        # get_default_session calls client.ensure_unlocked() which triggers PIN
        session = get_default_session(self._client)
        fn = encrypt_keyvalue if encrypt else decrypt_keyvalue
        return fn(
            session,
            address_n,
            _APP_KEY,
            value,
            ask_on_encrypt=True,
            ask_on_decrypt=True,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require(self) -> None:
        if self._client is None:
            raise RuntimeError("Trezor not connected. Call connect() first.")

    def __enter__(self) -> "TrezorManager":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()
