#!/usr/bin/env python3
"""
TrezorProtector — graphical user interface.

Run with:  python gui.py
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

# ── Verify project dependencies before anything else ──────────────────────
try:
    from trezor_protector.vault import Vault, DEFAULT_VAULT_PATH
    from trezor_protector.trezor import TrezorManager
    from trezor_protector.crypto import encrypt as aes_enc
    from trezor_protector.crypto import decrypt as aes_dec
    from trezor_protector.passwords import generate_password, pack, unpack
    from trezor_protector.files import decrypt_file, encrypt_file, read_encrypted
except ImportError as _ie:
    import tkinter as _tk
    _tk.Tk().withdraw()
    messagebox.showerror(
        "TrezorProtector — missing dependencies",
        f"{_ie}\n\nRun:  pip install -r requirements.txt",
    )
    sys.exit(1)

# ── Appearance ─────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# GitHub-inspired dark palette
BG      = "#0d1117"
SURFACE = "#161b22"
CARD    = "#21262d"
BORDER  = "#30363d"
ACCENT  = "#58a6ff"
SUCCESS = "#3fb950"
WARN    = "#d29922"
DANGER  = "#f85149"
TXT     = "#e6edf3"
MUTED   = "#8b949e"


# ══════════════════════════════════════════════════════════════════════════
#  _GUICallbacks — produces pin_callback / button_callback for AppManifest
#  (trezorlib 0.20+ no longer uses a UI object; it takes two plain callables)
# ══════════════════════════════════════════════════════════════════════════

class _GUICallbacks:
    """
    Provides pin_callback and button_callback for trezorlib 0.20+ AppManifest.

    Must be created in the main thread.  Trezor I/O runs in a worker thread;
    pin_callback blocks the worker thread via threading.Event and pops a
    Tkinter dialog via CTk.after() (which is thread-safe).
    """

    def __init__(self, app: "App", on_status: Callable[[str], None]) -> None:
        self._app = app
        self._on_status = on_status
        self._pin_event: threading.Event = threading.Event()
        self._pin_value: Optional[str] = None

    # ── trezorlib 0.20 callback interface ─────────────────────────────────

    def pin_callback(self, req) -> str:  # req: messages.PinMatrixRequest
        """Show PIN dialog in main thread; block worker thread until submitted."""
        self._pin_event.clear()
        self._pin_value = None
        self._status("PIN required — enter your Trezor PIN…")
        self._app.after(0, lambda: _PinDialog(self._app, self._receive_pin))
        if not self._pin_event.wait(timeout=120):
            raise RuntimeError("PIN entry timed out (120 s)")
        if self._pin_value is None:
            raise RuntimeError("PIN entry was cancelled")
        return self._pin_value

    def button_callback(self, req) -> None:  # req: messages.ButtonRequest
        """Device is waiting for a physical button press — update status only."""
        self._status("Confirm the action on your Trezor device…")

    # internal helpers -------------------------------------------------------

    def _receive_pin(self, pin: Optional[str]) -> None:
        self._pin_value = pin
        self._pin_event.set()

    def _status(self, msg: str) -> None:
        self._app.after(0, lambda: self._on_status(msg))


# ══════════════════════════════════════════════════════════════════════════
#  PIN entry dialog  (3×3 positional keypad — Trezor One / fallback)
# ══════════════════════════════════════════════════════════════════════════

class _PinDialog(ctk.CTkToplevel):
    """
    Positional PIN entry matching the standard Trezor numpad layout:

        7  8  9
        4  5  6
        1  2  3

    The device screen shows the scrambled numbers; the user clicks positions
    here to indicate which digit is at each spot.

    Trezor Model T / Safe 3 / Safe 5 handle PIN directly on-device; on those
    models this dialog may still appear as a fallback.
    """

    def __init__(self, parent: ctk.CTk, callback: Callable[[Optional[str]], None]) -> None:
        super().__init__(parent)
        self._cb = callback
        self._pin = ""

        self.title("Trezor — Enter PIN")
        self.geometry("320x440")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.grab_set()
        self.focus_force()

        ctk.CTkLabel(
            self,
            text="Enter PIN",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            self,
            text=(
                "Click positions as shown on your Trezor screen.\n"
                "Layout:   7  8  9  /  4  5  6  /  1  2  3"
            ),
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
            justify="center",
        ).pack(pady=(0, 8))

        # PIN dot display
        self._dots_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            self,
            textvariable=self._dots_var,
            font=ctk.CTkFont(size=30),
            text_color=ACCENT,
        ).pack(pady=6)

        # 3×3 grid
        grid_frame = ctk.CTkFrame(self, fg_color="transparent")
        grid_frame.pack(pady=4)
        for label, row, col in [
            ("7", 0, 0), ("8", 0, 1), ("9", 0, 2),
            ("4", 1, 0), ("5", 1, 1), ("6", 1, 2),
            ("1", 2, 0), ("2", 2, 1), ("3", 2, 2),
        ]:
            ctk.CTkButton(
                grid_frame,
                text=label,
                width=74,
                height=62,
                font=ctk.CTkFont(size=22, weight="bold"),
                command=lambda p=label: self._press(p),
            ).grid(row=row, column=col, padx=4, pady=4)

        # Action row
        act = ctk.CTkFrame(self, fg_color="transparent")
        act.pack(pady=12, fill="x", padx=24)
        ctk.CTkButton(
            act, text="⌫  Back", width=120,
            fg_color=CARD, hover_color=BORDER,
            command=self._backspace,
        ).pack(side="left")
        ctk.CTkButton(
            act, text="Confirm  ✓", width=130,
            fg_color=ACCENT, hover_color="#3d8bdb",
            command=self._confirm,
        ).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<BackSpace>", lambda _e: self._backspace())

    def _press(self, pos: str) -> None:
        if len(self._pin) < 9:
            self._pin += pos
            self._dots_var.set("●" * len(self._pin))

    def _backspace(self) -> None:
        self._pin = self._pin[:-1]
        self._dots_var.set("●" * len(self._pin))

    def _confirm(self) -> None:
        if not self._pin:
            return
        self._cb(self._pin)
        self._close()

    def _cancel(self) -> None:
        self._cb(None)
        self._close()

    def _close(self) -> None:
        self.grab_release()
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════
#  Add / Edit password dialog
# ══════════════════════════════════════════════════════════════════════════

class _PasswordDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent: ctk.CTk,
        *,
        title_text: str = "Add Password",
        name: str = "",
        username: str = "",
        url: str = "",
        password: str = "",
        notes: str = "",
        on_save: Callable[[dict], None],
    ) -> None:
        super().__init__(parent)
        self._on_save = on_save

        self.title(title_text)
        self.geometry("500x530")
        self.resizable(False, True)
        self.attributes("-topmost", True)
        self.grab_set()
        self.focus_force()

        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self, text=title_text, font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, columnspan=2, padx=24, pady=(20, 12), sticky="w")

        self._entries: dict[str, ctk.CTkEntry] = {}
        for i, (lbl, val) in enumerate(
            [("Site / Name", name), ("Username / Email", username), ("URL", url)], start=1
        ):
            ctk.CTkLabel(self, text=lbl, text_color=MUTED).grid(
                row=i, column=0, padx=24, pady=6, sticky="w"
            )
            e = ctk.CTkEntry(self, width=310)
            e.insert(0, val)
            e.grid(row=i, column=1, padx=(0, 24), pady=6, sticky="ew")
            self._entries[lbl] = e

        # Password row
        ctk.CTkLabel(self, text="Password", text_color=MUTED).grid(
            row=4, column=0, padx=24, pady=6, sticky="w"
        )
        pw_frame = ctk.CTkFrame(self, fg_color="transparent")
        pw_frame.grid(row=4, column=1, padx=(0, 24), pady=6, sticky="ew")

        self._pw_showing = False
        self._pw_entry = ctk.CTkEntry(pw_frame, width=200, show="●")
        self._pw_entry.insert(0, password)
        self._pw_entry.pack(side="left")

        ctk.CTkButton(
            pw_frame, text="👁", width=36, fg_color=CARD, hover_color=BORDER,
            command=self._toggle_pw,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            pw_frame, text="⚡ Gen", width=68, fg_color=SURFACE, hover_color=BORDER,
            command=self._gen_pw,
        ).pack(side="left")

        # Notes
        ctk.CTkLabel(self, text="Notes", text_color=MUTED).grid(
            row=5, column=0, padx=24, pady=6, sticky="nw"
        )
        self._notes = ctk.CTkTextbox(self, width=310, height=90)
        self._notes.insert("1.0", notes)
        self._notes.grid(row=5, column=1, padx=(0, 24), pady=6, sticky="ew")

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.grid(row=6, column=0, columnspan=2, pady=18, padx=24, sticky="e")
        ctk.CTkButton(
            btn_row, text="Cancel", width=100, fg_color=CARD, hover_color=BORDER,
            command=self._close,
        ).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="Save", width=100, command=self._save).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", self._close)

    def _toggle_pw(self) -> None:
        self._pw_showing = not self._pw_showing
        self._pw_entry.configure(show="" if self._pw_showing else "●")

    def _gen_pw(self) -> None:
        pw = generate_password(20)
        self._pw_entry.delete(0, "end")
        self._pw_entry.insert(0, pw)
        self._pw_entry.configure(show="")
        self._pw_showing = True

    def _save(self) -> None:
        name = self._entries["Site / Name"].get().strip()
        pw = self._pw_entry.get()
        if not name:
            messagebox.showwarning("Required", "Site / Name is required.", parent=self)
            return
        if not pw:
            messagebox.showwarning("Required", "Password is required.", parent=self)
            return
        self._on_save({
            "name": name,
            "username": self._entries["Username / Email"].get().strip(),
            "url": self._entries["URL"].get().strip(),
            "password": pw,
            "notes": self._notes.get("1.0", "end").strip(),
        })
        self._close()

    def _close(self) -> None:
        self.grab_release()
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════
#  Sidebar
# ══════════════════════════════════════════════════════════════════════════

class _Sidebar(ctk.CTkFrame):
    def __init__(self, parent: "App") -> None:
        super().__init__(parent, width=215, fg_color=SURFACE, corner_radius=0)
        self.pack_propagate(False)
        self._app = parent
        self._nav_btns: dict[str, ctk.CTkButton] = {}

        # Logo
        ctk.CTkLabel(
            self,
            text="🔐 TrezorProtector",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=TXT,
        ).pack(padx=16, pady=(22, 8), anchor="w")

        ctk.CTkFrame(self, height=1, fg_color=BORDER).pack(fill="x", padx=12, pady=6)

        # Nav buttons
        for page, icon_label in [
            ("passwords", "🔑   Passwords"),
            ("files",     "📁   Files"),
        ]:
            btn = ctk.CTkButton(
                self,
                text=icon_label,
                anchor="w",
                fg_color="transparent",
                hover_color=CARD,
                text_color=TXT,
                corner_radius=8,
                font=ctk.CTkFont(size=13),
                command=lambda p=page: self._app.show_page(p),
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_btns[page] = btn

        # Push status to bottom
        ctk.CTkFrame(self, fg_color="transparent").pack(expand=True, fill="y")

        ctk.CTkFrame(self, height=1, fg_color=BORDER).pack(fill="x", padx=12, pady=6)

        # Trezor status
        self._dot_label = ctk.CTkLabel(self, text="⚫  Not connected", text_color=MUTED,
                                        font=ctk.CTkFont(size=11))
        self._dot_label.pack(padx=16, pady=(0, 4), anchor="w")
        self._device_label = ctk.CTkLabel(self, text="", text_color=MUTED,
                                           font=ctk.CTkFont(size=10))
        self._device_label.pack(padx=16, pady=(0, 8), anchor="w")

        # Lock button
        ctk.CTkButton(
            self,
            text="🔒   Lock vault",
            anchor="w",
            fg_color="transparent",
            hover_color=CARD,
            text_color=DANGER,
            corner_radius=8,
            font=ctk.CTkFont(size=13),
            command=self._app.lock_vault,
        ).pack(fill="x", padx=8, pady=(0, 16))

    def set_active(self, page: str) -> None:
        for p, btn in self._nav_btns.items():
            btn.configure(
                fg_color=CARD if p == page else "transparent",
                font=ctk.CTkFont(size=13, weight="bold" if p == page else "normal"),
            )

    def set_device(self, connected: bool, model: str = "", label: str = "") -> None:
        if connected:
            self._dot_label.configure(text="🟢  Connected", text_color=SUCCESS)
            self._device_label.configure(text=f"{model}  ·  {label}", text_color=MUTED)
        else:
            self._dot_label.configure(text="⚫  Not connected", text_color=MUTED)
            self._device_label.configure(text="")


# ══════════════════════════════════════════════════════════════════════════
#  Lock / welcome page
# ══════════════════════════════════════════════════════════════════════════

class _LockPage(ctk.CTkFrame):
    def __init__(self, parent: "App") -> None:
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._app = parent

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.place(relx=0.5, rely=0.45, anchor="center")

        ctk.CTkLabel(inner, text="🔐", font=ctk.CTkFont(size=72)).pack(pady=(0, 12))
        ctk.CTkLabel(
            inner,
            text="TrezorProtector",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color=TXT,
        ).pack()
        ctk.CTkLabel(
            inner,
            text="Password manager & file encryption\nbacked by your Trezor hardware wallet.",
            text_color=MUTED,
            font=ctk.CTkFont(size=13),
            justify="center",
        ).pack(pady=(6, 28))

        self._unlock_btn = ctk.CTkButton(
            inner,
            text="🔓   Unlock with Trezor",
            width=270,
            height=50,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._app.unlock,
        )
        self._unlock_btn.pack(pady=6)

        self._create_btn = ctk.CTkButton(
            inner,
            text="✨   Create New Vault",
            width=270,
            height=42,
            fg_color=CARD,
            hover_color=BORDER,
            font=ctk.CTkFont(size=13),
            command=self._app.create_vault,
        )
        self._create_btn.pack(pady=6)

        self._status_lbl = ctk.CTkLabel(
            inner,
            text="",
            text_color=MUTED,
            font=ctk.CTkFont(size=12),
            wraplength=340,
            justify="center",
        )
        self._status_lbl.pack(pady=14)

    def refresh_buttons(self) -> None:
        has_vault = Vault(self._app.vault_path).exists
        self._unlock_btn.configure(
            state="normal" if has_vault else "disabled",
            text="🔓   Unlock with Trezor" if has_vault else "🔓   No vault — create one first",
        )

    def set_status(self, msg: str, color: str = MUTED) -> None:
        self._status_lbl.configure(text=msg, text_color=color)

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self._unlock_btn.configure(state=state)
        self._create_btn.configure(state=state)
        if not busy:
            self.refresh_buttons()


# ══════════════════════════════════════════════════════════════════════════
#  Passwords page  (left list + right detail panel)
# ══════════════════════════════════════════════════════════════════════════

class _PasswordsPage(ctk.CTkFrame):
    def __init__(self, parent: "App") -> None:
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._app = parent
        self._all_entries: list[dict] = []

        # ── Left: list panel ──────────────────────────────────────────────
        left = ctk.CTkFrame(self, width=330, fg_color=SURFACE, corner_radius=0)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        # Search + Add button
        top_bar = ctk.CTkFrame(left, fg_color=SURFACE)
        top_bar.pack(fill="x", padx=10, pady=10)
        self._search = ctk.CTkEntry(top_bar, placeholder_text="🔍  Search…", width=220)
        self._search.pack(side="left", expand=True, fill="x")
        self._search.bind("<KeyRelease>", lambda _: self._apply_filter())
        ctk.CTkButton(
            top_bar, text="+", width=36, font=ctk.CTkFont(size=18, weight="bold"),
            command=self._open_add_dialog,
        ).pack(side="left", padx=(6, 0))

        ctk.CTkLabel(left, text="PASSWORDS", text_color=MUTED,
                     font=ctk.CTkFont(size=10)).pack(anchor="w", padx=14, pady=(2, 0))

        self._list_scroll = ctk.CTkScrollableFrame(left, fg_color=SURFACE, corner_radius=0)
        self._list_scroll.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Right: detail panel ───────────────────────────────────────────
        self._right = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self._right.pack(side="right", fill="both", expand=True)
        self._show_placeholder()

    # ── Data ───────────────────────────────────────────────────────────────

    def reload(self) -> None:
        self._all_entries = self._app.vault.get_passwords()
        self._render_list(self._all_entries)

    def _apply_filter(self) -> None:
        q = self._search.get().strip().lower()
        filtered = (
            [e for e in self._all_entries
             if q in e["name"].lower()
             or q in e.get("username", "").lower()
             or q in e.get("url", "").lower()]
            if q else self._all_entries
        )
        self._render_list(filtered)

    # ── List rendering ──────────────────────────────────────────────────────

    def _render_list(self, entries: list[dict]) -> None:
        for w in self._list_scroll.winfo_children():
            w.destroy()
        if not entries:
            ctk.CTkLabel(self._list_scroll, text="No entries found.",
                         text_color=MUTED).pack(pady=24)
            return
        for entry in entries:
            self._make_entry_card(entry)

    def _make_entry_card(self, entry: dict) -> None:
        card = ctk.CTkFrame(
            self._list_scroll, fg_color=CARD, corner_radius=8, cursor="hand2"
        )
        card.pack(fill="x", padx=4, pady=3)

        ctk.CTkLabel(
            card,
            text=entry["name"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TXT,
            anchor="w",
        ).pack(anchor="w", padx=12, pady=(8, 1))
        ctk.CTkLabel(
            card,
            text=entry.get("username") or entry.get("url") or "",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            anchor="w",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        for widget in (card,):
            widget.bind("<Button-1>", lambda _, e=entry: self._open_detail(e))
        for child in card.winfo_children():
            child.bind("<Button-1>", lambda _, e=entry: self._open_detail(e))

    # ── Detail panel ────────────────────────────────────────────────────────

    def _show_placeholder(self) -> None:
        for w in self._right.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self._right, text="← Select an entry to view it",
            text_color=MUTED, font=ctk.CTkFont(size=14),
        ).place(relx=0.5, rely=0.5, anchor="center")

    def _open_detail(self, entry: dict) -> None:
        for w in self._right.winfo_children():
            w.destroy()

        try:
            pw_data = unpack(aes_dec(self._app.master_key,
                                     bytes.fromhex(entry["encrypted_data"])))
        except Exception:
            ctk.CTkLabel(self._right, text="⚠  Decryption failed",
                         text_color=DANGER).place(relx=0.5, rely=0.5, anchor="center")
            return

        # ── Header bar ───
        hdr = ctk.CTkFrame(self._right, fg_color=SURFACE, corner_radius=0)
        hdr.pack(fill="x")

        ctk.CTkLabel(
            hdr, text=entry["name"],
            font=ctk.CTkFont(size=20, weight="bold"), text_color=TXT, anchor="w",
        ).pack(side="left", padx=20, pady=14)

        acts = ctk.CTkFrame(hdr, fg_color="transparent")
        acts.pack(side="right", padx=12, pady=10)
        ctk.CTkButton(
            acts, text="✏  Edit", width=80, fg_color=CARD, hover_color=BORDER,
            command=lambda: self._open_edit_dialog(entry, pw_data),
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            acts, text="🗑  Delete", width=92, fg_color=DANGER, hover_color="#c0392b",
            command=lambda: self._delete(entry),
        ).pack(side="left", padx=4)

        # ── Scrollable field area ───
        scroll = ctk.CTkScrollableFrame(self._right, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=12)

        for lbl, val in [
            ("Username", entry.get("username") or "—"),
            ("URL",      entry.get("url") or "—"),
            ("Created",  (entry.get("created_at") or "")[:10]),
            ("Updated",  (entry.get("updated_at") or "")[:10]),
        ]:
            self._info_row(scroll, lbl, val)

        # Password row
        pw_row = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=8)
        pw_row.pack(fill="x", pady=4)
        ctk.CTkLabel(pw_row, text="Password", text_color=MUTED,
                     width=100, anchor="w").pack(side="left", padx=12)

        self._pw_var     = ctk.StringVar(value="●" * min(len(pw_data["password"]), 22))
        self._pw_plain   = pw_data["password"]
        self._pw_visible = False

        ctk.CTkLabel(pw_row, textvariable=self._pw_var, text_color=TXT, anchor="w").pack(
            side="left", expand=True
        )
        ctk.CTkButton(
            pw_row, text="👁", width=36, fg_color=SURFACE, hover_color=BORDER,
            command=self._toggle_pw,
        ).pack(side="right", padx=4, pady=6)
        ctk.CTkButton(
            pw_row, text="📋 Copy", width=88, fg_color=SURFACE, hover_color=BORDER,
            command=lambda: self._copy(pw_data["password"], entry["name"]),
        ).pack(side="right", padx=4)

        if pw_data.get("notes"):
            ctk.CTkLabel(scroll, text="Notes", text_color=MUTED,
                         anchor="w").pack(anchor="w", pady=(12, 4))
            tb = ctk.CTkTextbox(scroll, height=88, fg_color=CARD, state="normal")
            tb.insert("1.0", pw_data["notes"])
            tb.configure(state="disabled")
            tb.pack(fill="x")

    def _info_row(self, parent: ctk.CTkFrame, label: str, value: str) -> None:
        row = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=8)
        row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text=label, text_color=MUTED, width=100, anchor="w").pack(
            side="left", padx=12, pady=9
        )
        ctk.CTkLabel(row, text=value, text_color=TXT, anchor="w").pack(
            side="left", expand=True
        )

    def _toggle_pw(self) -> None:
        if self._pw_visible:
            self._pw_var.set("●" * min(len(self._pw_plain), 22))
        else:
            self._pw_var.set(self._pw_plain)
        self._pw_visible = not self._pw_visible

    def _copy(self, pw: str, name: str) -> None:
        try:
            import pyperclip
            pyperclip.copy(pw)
            messagebox.showinfo("Copied", f"Password for '{name}' copied to clipboard.",
                                parent=self)
        except Exception:
            messagebox.showinfo("Password", f"Your password:\n{pw}", parent=self)

    # ── CRUD ────────────────────────────────────────────────────────────────

    def _open_add_dialog(self) -> None:
        _PasswordDialog(self._app, title_text="Add Password", on_save=self._do_add)

    def _do_add(self, data: dict) -> None:
        blob = pack(data["password"], data.get("notes", ""))
        enc  = aes_enc(self._app.master_key, blob)
        self._app.vault.add_password(data["name"], data["username"], data["url"], enc)
        self.reload()

    def _open_edit_dialog(self, entry: dict, pw_data: dict) -> None:
        _PasswordDialog(
            self._app,
            title_text="Edit Password",
            name=entry["name"],
            username=entry.get("username", ""),
            url=entry.get("url", ""),
            password=pw_data["password"],
            notes=pw_data.get("notes", ""),
            on_save=lambda data, eid=entry["id"]: self._do_edit(eid, data),
        )

    def _do_edit(self, entry_id: str, data: dict) -> None:
        blob = pack(data["password"], data.get("notes", ""))
        enc  = aes_enc(self._app.master_key, blob)
        self._app.vault.update_password(
            entry_id,
            name=data["name"],
            username=data["username"],
            url=data["url"],
            encrypted_data=enc,
        )
        self.reload()
        self._show_placeholder()

    def _delete(self, entry: dict) -> None:
        if messagebox.askyesno("Delete", f"Delete '{entry['name']}'?", parent=self):
            self._app.vault.delete_password(entry["id"])
            self.reload()
            self._show_placeholder()


# ══════════════════════════════════════════════════════════════════════════
#  Files page
# ══════════════════════════════════════════════════════════════════════════

class _FilesPage(ctk.CTkFrame):
    def __init__(self, parent: "App") -> None:
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self._app = parent

        # Center the content vertically
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.place(relx=0.5, rely=0.45, anchor="center")

        ctk.CTkLabel(
            inner, text="File Encryption",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=(0, 4))
        ctk.CTkLabel(
            inner,
            text="Encrypt any file with your Trezor key.\nOnly the device that created this vault can decrypt it.",
            text_color=MUTED, font=ctk.CTkFont(size=13), justify="center",
        ).pack(pady=(0, 22))

        # Visual drop-zone hint
        zone = ctk.CTkFrame(
            inner, width=460, height=120,
            fg_color=CARD, border_width=2, border_color=BORDER, corner_radius=14,
        )
        zone.pack(pady=4)
        zone.pack_propagate(False)
        ctk.CTkLabel(
            zone,
            text="📂   Select a file using the buttons below",
            text_color=MUTED, font=ctk.CTkFont(size=13),
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Buttons
        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(pady=18)
        for text, cmd, fg in [
            ("🔒  Encrypt File", self._encrypt, ACCENT),
            ("🔓  Decrypt File", self._decrypt, CARD),
            ("👁   View Content", self._view,    CARD),
        ]:
            ctk.CTkButton(
                btn_row, text=text, width=168, height=46,
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color=fg,
                hover_color=BORDER if fg == CARD else "#3d8bdb",
                command=cmd,
            ).pack(side="left", padx=6)

        # Activity log
        ctk.CTkLabel(inner, text="Activity", text_color=MUTED,
                     font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(8, 2))
        self._log = ctk.CTkTextbox(inner, width=560, height=160, fg_color=SURFACE,
                                    state="disabled", font=ctk.CTkFont(size=11, family="Courier"))
        self._log.pack()

    def _log_write(self, msg: str) -> None:
        self._log.configure(state="normal")
        self._log.insert("end", msg + "\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def _encrypt(self) -> None:
        path = filedialog.askopenfilename(title="Choose file to encrypt", parent=self)
        if not path:
            return
        src = Path(path)
        try:
            dst = encrypt_file(self._app.master_key, src)
            self._log_write(f"✅  {src.name}  →  {dst.name}")
            messagebox.showinfo("Encrypted", f"Saved as:\n{dst}", parent=self)
        except Exception as exc:
            self._log_write(f"❌  {exc}")
            messagebox.showerror("Encryption failed", str(exc), parent=self)

    def _decrypt(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose .tpenc file",
            filetypes=[("TrezorProtector files", "*.tpenc"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        src = Path(path)
        try:
            dst, orig = decrypt_file(self._app.master_key, src)
            self._log_write(f"✅  {src.name}  →  {orig}")
            messagebox.showinfo("Decrypted", f"Saved as:\n{dst}", parent=self)
        except Exception as exc:
            self._log_write(f"❌  {exc}")
            messagebox.showerror("Decryption failed", str(exc), parent=self)

    def _view(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose .tpenc file to view",
            filetypes=[("TrezorProtector files", "*.tpenc"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        src = Path(path)
        try:
            content, orig = read_encrypted(self._app.master_key, src)
        except Exception as exc:
            self._log_write(f"❌  {exc}")
            messagebox.showerror("Error", str(exc), parent=self)
            return

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            messagebox.showinfo(
                "Binary file",
                f"'{orig}' is a binary file ({len(content):,} bytes).\n"
                "Use Decrypt to save it to disk.",
                parent=self,
            )
            self._log_write(f"ℹ  {orig} is binary ({len(content):,} B)")
            return

        viewer = ctk.CTkToplevel(self)
        viewer.title(f"View (decrypted) — {orig}")
        viewer.geometry("740x520")
        viewer.attributes("-topmost", True)
        tb = ctk.CTkTextbox(viewer, state="normal", font=ctk.CTkFont(size=12, family="Courier"))
        tb.pack(fill="both", expand=True, padx=12, pady=12)
        tb.insert("1.0", text)
        tb.configure(state="disabled")
        self._log_write(f"👁   {src.name}  ({orig}, {len(content):,} B)")


# ══════════════════════════════════════════════════════════════════════════
#  Main application window
# ══════════════════════════════════════════════════════════════════════════

class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("TrezorProtector")
        self.geometry("1120x720")
        self.minsize(900, 620)
        self.configure(fg_color=BG)

        # ── App state ──────────────────────────────────────────────────────
        self.vault_path: Path = DEFAULT_VAULT_PATH
        self.trezor:     Optional[TrezorManager] = None
        self.master_key: Optional[bytes]         = None
        self.vault:      Optional[Vault]          = None

        # ── Layout: sidebar | stacked content frames ───────────────────────
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar = _Sidebar(self)
        self._sidebar.grid(row=0, column=0, sticky="nsew")

        content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        # All pages live in the same cell; lift() brings one to front
        self._lock_page = _LockPage(self)
        self._pw_page   = _PasswordsPage(self)
        self._file_page = _FilesPage(self)

        for pg in (self._lock_page, self._pw_page, self._file_page):
            pg.grid(in_=content, row=0, column=0, sticky="nsew")

        self._show_lock()

    # ── Navigation ──────────────────────────────────────────────────────────

    def _show_lock(self) -> None:
        self._lock_page.refresh_buttons()
        self._lock_page.lift()

    def show_page(self, page: str) -> None:
        if self.master_key is None:
            return
        if page == "passwords":
            self._pw_page.reload()
            self._pw_page.lift()
        elif page == "files":
            self._file_page.lift()
        self._sidebar.set_active(page)

    def lock_vault(self) -> None:
        if self.trezor:
            self.trezor.disconnect()
            self.trezor = None
        self.master_key = None
        self.vault      = None
        self._sidebar.set_device(False)
        self._show_lock()

    # ── Vault creation ──────────────────────────────────────────────────────

    def create_vault(self) -> None:
        v = Vault(self.vault_path)
        if v.exists and not messagebox.askyesno(
            "Overwrite vault?",
            "A vault already exists.\n"
            "Creating a new one will REPLACE it and you will lose\n"
            "all stored passwords.\n\nContinue?",
            parent=self,
        ):
            return

        self._lock_page.set_busy(True)
        self._lock_page.set_status("Connecting to Trezor…")

        trezor_ui = _GUICallbacks(self, on_status=self._lock_page.set_status)

        def worker():
            trezor = TrezorManager()
            trezor.connect(
                pin_callback=trezor_ui.pin_callback,
                button_callback=trezor_ui.button_callback,
            )
            info    = trezor.get_info()
            raw_key = os.urandom(32)
            enc_key = trezor.encrypt_master_key(raw_key)
            new_vault = Vault(self.vault_path)
            new_vault.create(enc_key)
            return trezor, raw_key, new_vault, info

        self._run_async(worker, self._on_vault_ready)

    # ── Vault unlock ────────────────────────────────────────────────────────

    def unlock(self) -> None:
        v = Vault(self.vault_path)
        if not v.exists:
            messagebox.showwarning("No vault", "No vault found. Create one first.", parent=self)
            return

        self._lock_page.set_busy(True)
        self._lock_page.set_status("Connecting to Trezor…")

        trezor_ui = _GUICallbacks(self, on_status=self._lock_page.set_status)

        def worker():
            trezor = TrezorManager()
            trezor.connect(
                pin_callback=trezor_ui.pin_callback,
                button_callback=trezor_ui.button_callback,
            )
            info    = trezor.get_info()
            v.load()
            enc_key    = v.get_encrypted_master_key()
            master_key = trezor.decrypt_master_key(enc_key)
            return trezor, master_key, v, info

        self._run_async(worker, self._on_vault_ready)

    def _on_vault_ready(self, result) -> None:
        self._lock_page.set_busy(False)
        if isinstance(result, Exception):
            self._lock_page.set_status(f"⚠  {result}", DANGER)
            return
        trezor, master_key, vault, info = result
        self.trezor     = trezor
        self.master_key = master_key
        self.vault      = vault
        self._sidebar.set_device(True, info["model"], info["label"])
        self.show_page("passwords")

    # ── Threading helper ────────────────────────────────────────────────────

    def _run_async(
        self,
        worker: Callable[[], object],
        callback: Callable[[object], None],
    ) -> None:
        """Run *worker* in a daemon thread; call *callback(result)* in main thread."""
        def _thread():
            try:
                result = worker()
            except Exception as exc:
                result = exc
            self.after(0, lambda: callback(result))

        threading.Thread(target=_thread, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════

def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
