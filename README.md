# TrezorProtector

Password manager **and** file encryption in one tool, with a twist no
software-only manager has: the vault physically cannot be opened without
pressing a button on your Trezor.

v2 is a ground-up rewrite of the core in **Rust** (memory-safe, zeroized
secrets, pure-Rust crypto) with a **desktop app**, a **CLI**, and a
**Chrome extension** backed by a native messaging host. The original
Python implementation (v1: `main.py`, `gui.py`) still lives at the repo
root and received bug fixes; new development happens in
`trezor_protector/rust/`.

See [SECURITY.md](SECURITY.md) for the full threat analysis (recent
password-manager CVEs and how each one is addressed).

```
+-------------+   native    +---------+  USB   +--------+
| Chrome ext. | <---------> | tp-host | <----> | Trezor |
+-------------+  messaging  +----+----+        +--------+
                PIN dialogs -----+ tp-core (Rust)
+-------------+                  |
|  tp  (CLI)  | <----------------+
+-------------+                  |
|tp-gui (app) | <----------------+
+-------------+                  v
                    ~/.trezorprotector/vault.json   (fully encrypted)
```

## Building

Requires Rust 1.75+ ([rustup](https://rustup.rs)), no other toolchain.

```console
cd trezor_protector/rust
cargo build --release    # target/release: tp, tp-host, tp-gui
cargo test               # 28 unit tests incl. RFC 6238 vectors
```

Windows binaries ship with an embedded icon/version info; the CLI uses
colored output on Windows 10+, Linux and macOS terminals.

### Linux

Verified on Ubuntu 24.04 (build + full test suite). One-shot setup:

```console
sudo apt install build-essential pkg-config libusb-1.0-0-dev   # prerequisites
cd trezor_protector/rust
./install-linux.sh [chrome-extension-id]
```

The script builds, installs `tp`/`tp-host` to `~/.local/bin`, sets up the
udev rules from
[51-trezor.rules](trezor_protector/rust/assets/51-trezor.rules)
(skip if Trezor Suite already installed them) and optionally registers the
Chrome native messaging host. The host manifest covers Chrome, Chromium,
Brave and Edge on Linux, plus Chrome/Chromium on macOS.

## Desktop app (tp-gui)

`tp-gui` is a native window for everyday use:

- **Unlock with Trezor** — PIN pad and passphrase prompts as native dialogs.
- Browse/search entries, reveal or copy passwords (auto-clearing clipboard),
  live 2FA codes, password history.
- Add, edit, delete entries; built-in generator (passwords & passphrases).
- Encrypt/decrypt files via the file picker.
- Auto-locks after 5 idle minutes; keys are zeroized on lock.

It also provides the dialog windows the Chrome flow uses: when the browser
needs an unlock, `tp-host` opens `tp-gui`'s **native** connect/PIN/passphrase
dialogs outside the browser (falling back to in-popup entry if `tp-gui`
isn't next to `tp-host`).

## CLI quick start

```console
tp init                          # create a vault bound to your Trezor
tp pw add github -u alice --url https://github.com -g   # generate & store
tp pw add aws --totp JBSWY3DPEHPK3PXP                   # store a 2FA secret
tp pw list                       # metadata table (passwords stay hidden)
tp pw copy github                # clipboard, auto-clears after 30 s
tp totp aws                      # current 2FA code + validity countdown
tp pw update github --generate   # rotate (old password kept in history)
tp pw history github             # see previous passwords
tp audit --hibp                  # weak/reused/stale + breach check (k-anonymity)

tp file encrypt tax-return.pdf --shred-original
tp file decrypt tax-return.pdf.tpenc
tp file view secrets.txt.tpenc   # print without touching disk
tp file shred old-notes.txt      # secure overwrite + delete

tp vault export backup.tpbackup  # password-protected recovery file
                                 # (works even if the Trezor is lost!)
tp vault import backup.tpbackup
tp vault rotate-key              # re-wrap everything under a fresh key
tp migrate                       # upgrade a v1 (Python) vault in place
```

Global: `--vault <path>` or `TREZOR_PROTECTOR_VAULT` env var.

## Saving passwords from the browser

Log in anywhere as usual. The extension's passive observer (it injects no
UI into pages) notices the submitted form; if that password isn't in the
vault yet — or differs from the stored one — the toolbar icon gets a green
**＋** badge. Open the popup and click **Save to vault** / **Update entry**.
If the vault is locked you'll be asked to confirm on the Trezor first;
pending credentials are held only in memory and are discarded when the tab
or browser closes.

## Chrome extension setup

1. `cd trezor_protector/rust && cargo build --release`
2. Open `chrome://extensions`, enable *Developer mode*, click *Load
   unpacked* and select the `trezor_protector/chrome-extension/` folder.
3. Copy the extension ID shown on the card, then register the host:

   ```console
   .\trezor_protector\rust\target\release\tp-host.exe install --extension-id <that-id>
   ```

4. Click the shield icon → **Unlock with Trezor** → confirm on the device.

What the extension gives you:

- Entries for the current site float to the top, highlighted.
- **Fill** — one click, top frame only, domain-checked (a mismatch shows a
  phishing warning instead of filling).
- Save/update prompts after you log in on any site.
- **Copy pass / user** — clipboard auto-clears after ~35 s.
- **2FA codes** with a live countdown, click to copy.
- Password & passphrase generator.
- Auto-lock (1 min – 1 h, default 5 min); locking wipes keys from memory.
- Trezor One PIN entry via native OS dialogs (or the popup matrix as
  fallback) — positions only, the layout lives on the device screen.

The extension injects **nothing** into web pages — no dropdowns, no
overlays — which makes the 2025 DOM-clickjacking attack class against
password-manager extensions structurally impossible here.

## What's new in v2 (vs the Python v1)

| Area | v1 | v2 |
|------|----|----|
| Language | Python | Rust, `#![forbid(unsafe_code)]`, zeroized secrets |
| Vault format | metadata in plaintext, per-entry blobs | everything encrypted in one authenticated blob |
| Files | whole file in RAM | streaming 1 MiB chunks, per-file keys, truncation-proof |
| Desktop | tkinter GUI | native egui app + colored CLI |
| Browser | — | Chrome/Edge extension + native host, save & fill |
| 2FA | — | TOTP storage & codes (RFC 6238) |
| Hygiene | — | audit: weak / reused / stale / breached (HIBP k-anonymity) |
| Recovery | none if device lost | Argon2id-encrypted export/import |
| Key mgmt | — | key rotation, password history |
| Extras | — | passphrase generator, secure shred, clipboard auto-clear, atomic writes + backups |

## Vault compatibility

`tp migrate` upgrades a v1 vault in place (the original is kept as
`vault.v1.bak`). The Trezor wrapping is unchanged, so the same device that
created the v1 vault unlocks the migrated one. Legacy `.tpenc` (TPENC1)
files decrypt transparently; new files are written in the TPENC2 format.

## License

MIT — see [LICENSE](LICENSE).
