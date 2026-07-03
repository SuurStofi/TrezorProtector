# TrezorProtector — Security Design & Threat Analysis

This document explains how TrezorProtector v2 defends against the
vulnerability classes that have actually hit password managers and hardware
wallets in recent years, and which design decisions each one motivated.

## Architecture in one paragraph

A random 256-bit master key is generated on the host and immediately
*wrapped* by the Trezor with `CipherKeyValue` on path `m/10016'/0'`
(SLIP-0016 style). Only the wrapped form ever touches the disk. Unwrapping
requires the physical device **and a button press for every unlock**
(`ask_on_encrypt`/`ask_on_decrypt` are both set). The master key never
encrypts data directly: HKDF-SHA256 derives an independent subkey per
context (vault, files), and every AES-256-GCM ciphertext is bound to its
context through AAD, so a blob cut out of one place is rejected everywhere
else.

## Recent CVEs / disclosures and what we did about them

### 1. DOM-based extension clickjacking — VU#516608 (DEF CON 33, Aug 2025)
Eleven major password-manager extensions were shown to leak credentials,
card data and TOTP codes from a **single click on an attacker page**, by
overlaying or restyling the autofill UI those extensions inject into the
DOM. Several vendors were still unpatched months later.

**Mitigation (by construction):** the TrezorProtector extension injects
*no UI into web pages* — there is nothing for a malicious page to overlay,
restyle or spoof. The only content script is a passive observer for the
save-password feature: it watches form submissions and adds zero DOM
elements, so it presents no clickjacking surface either. Filling happens
only from the browser-owned popup (which pages cannot clickjack), only
after an explicit click, only into the **top frame** (`allFrames: false`),
and only after the tab's domain matches the entry's stored URL; mismatches
require an explicit, spelled-out confirmation. Credentials are fetched one
entry at a time and never cached in the extension. Captured submissions
awaiting a save decision live in `chrome.storage.session` (memory-only,
wiped when the browser closes) and the captured password is never handed
to the popup — only to the native host after the user clicks Save.

### 2. KeePass CVE-2023-32784 — master password recoverable from memory
KeePass 2.x left enough of the master password in process memory that it
could be reconstructed from a memory dump or swap file.

**Mitigation:** this is a core reason the rewrite is in Rust. All key
material lives in `SecretKey`/`Zeroizing` buffers that are wiped on drop
(`zeroize` uses compiler fences the optimizer cannot elide); decrypted
plaintexts are returned in self-wiping buffers; the vault's in-memory
entries are zeroized when it locks or the process exits. Python cannot make
these guarantees: immutable `str`/`bytes` copies of secrets stay on the heap
until the GC — and even then are not overwritten.

### 3. KeePass CVE-2023-24055 — config file triggers plaintext export
A writable config allowed an attacker to make the app silently export the
whole database in plaintext on next unlock.

**Mitigation:** TrezorProtector has no config-driven actions at all. Export
exists only as an interactive command that requires a device-confirmed
unlock *plus* a freshly typed backup password, and the output is always
Argon2id + AES-256-GCM encrypted. There is no code path that writes
plaintext secrets to disk.

### 4. Hardware attacks on Trezor devices
Known physical vectors include the Trezor One OLED power side channel
(CVE-2019-14353) and voltage-glitching work, most recently Ledger Donjon's
March 2025 evaluation of the Safe 3's STM32 microcontroller.

**Mitigation at the software layer:** every unlock demands a physical
button press, so stolen vault + stolen computer is still not enough; the
attacker needs the device in hand *and* the PIN. Enabling a **passphrase**
on the device raises this further — even full seed extraction from glitched
hardware does not reproduce the CipherKeyValue key without the passphrase.
`tp vault rotate-key` lets you re-wrap the vault instantly if a device is
suspected compromised or is being replaced.

### 5. C-library CVEs in the crypto stack
The Python version depended on `cryptography`, i.e. OpenSSL — a recurring
source of memory-safety advisories that you inherit whether or not the
vulnerable code path is used.

**Mitigation:** the Rust version uses the pure-Rust RustCrypto `aes-gcm`
(constant-time, AES-NI accelerated, externally audited) plus `argon2`,
`hkdf`, `hmac`, `sha2` from the same project. No OpenSSL, no C crypto. All
three crates compile with `#![forbid(unsafe_code)]`; release builds use
`panic = "abort"`, thin LTO and symbol stripping.

### 6. Clipboard exposure
Windows clipboard history (Win+V) and cloud clipboard sync can persist
copied passwords indefinitely; clipboard-sniffing malware is common.

**Mitigation:** every sensitive copy auto-clears — the CLI counts down and
wipes (only if the clipboard still holds our value), the extension
schedules a clear ~35 s after copying via an offscreen document.
*Limitation:* if Windows clipboard history is enabled, entries may persist
there; prefer **Fill** over copy in the browser, and consider disabling
clipboard history / sync.

## Weaknesses of the v1 formats that v2 removes

| # | v1 weakness | v2 fix |
|---|-------------|--------|
| 1 | Entry names, usernames, URLs stored in **plaintext** — full account map leaks with the file | Whole entry list encrypted as one blob; the file leaks only its size |
| 2 | Each entry sealed separately — silent **deletion/duplication/rollback** of entries undetectable | Single GCM tag over the whole list; any structural tamper fails decryption |
| 3 | No AAD — ciphertexts interchangeable between contexts | Every blob AAD-bound (vault / backup / file name / file chunk + index) |
| 4 | Master key used raw for everything | HKDF-SHA256 domain-separated subkeys per context |
| 5 | Whole file read into RAM to encrypt | Streaming 1 MiB chunks; per-file keys (random 16-byte salt) |
| 6 | Encrypted files could be **truncated** without detection | Chunk index in AAD + "last chunk" marker: reorder, drop, truncate, append all fail |
| 7 | Embedded filename allowed **path traversal** on restore | Basename-only sanitization (fixed in Python too) |
| 8 | Non-atomic vault writes — crash could destroy the vault | Temp file + fsync + backup + atomic rename (fixed in Python too) |
| 9 | `read_encrypted` returned (name, data) swapped — `file view` printed the filename | Fixed in Python; Rust API is typed |
| 10 | Vault world-readable on Unix | 0600 permissions on create |
| 11 | No recovery if the Trezor is lost | `tp vault export`: Argon2id (64 MiB, t=3) password-protected backup |

## Native messaging host hardening

- Chrome verifies the extension ID against `allowed_origins` in the host
  manifest (per-user install, no admin rights, registry `HKCU` only).
- The vault key exists **only in the host process**, never in the browser.
- `list` returns metadata only; passwords/TOTP secrets are fetched one
  entry per explicit user action.
- Idle auto-lock (default 5 min, max 4 h) drops and zeroizes all key
  material; browser disconnect kills the process outright.
- Trezor One PIN entry is relayed as **matrix positions** — the browser and
  the host never learn the actual digits; passphrases can always be entered
  on the device itself so the host machine never sees them.
- When the desktop app (`tp-gui`) is installed next to the host, PIN and
  passphrase prompts open as **native always-on-top windows outside the
  browser** — a compromised renderer or malicious extension cannot observe
  or overlay them. The popup grid remains as fallback.
- Vault writes from the browser are limited to two commands (`add`,
  `update_password`), both of which require an unlocked session — i.e. a
  physical device confirmation must have happened first.

## Breach checking without leaking passwords

`tp audit --hibp` uses the Have-I-Been-Pwned k-anonymity range API: only
the first 5 hex characters of the SHA-1 leave the machine (with
`Add-Padding: true` to blur even prefix traffic analysis); suffix matching
happens locally.

## Reporting

Found something? Please open a private report rather than a public issue.
Include reproduction steps and affected component (CLI / core / host /
extension).
