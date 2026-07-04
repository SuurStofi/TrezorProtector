# TrezorProtector — Attack Surface Analysis

An honest, itemised threat model: for each attack, what the design does, and
where the hard limits are. "Impossible" is used only where it is literally
true (e.g. decrypting without the key); everywhere else the claim is
"infeasible" or "mitigated", with the residual risk stated.

Legend: **M** mitigated · **P** partially mitigated (residual risk) · **O**
out of scope (stated so you can compensate elsewhere).

---

## 1. Attacker has the vault file only

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|1.1| Read passwords/metadata | **M** | Whole entry list is one AES-256-GCM blob; the file leaks only its size. No plaintext names/URLs (unlike v1). |
|1.2| **Brute-force the vault** | **M** | There is *no vault password to guess* — the key comes from the Trezor (CipherKeyValue) or the recovery phrase. Guessing AES-256 is 2²⁵⁶ work. |
|1.3| Tamper: flip bytes, delete/reorder/duplicate entries | **M** | One GCM tag authenticates the entire list; any change fails decryption. |
|1.4| Replay a blob from a file/backup into the vault | **M** | AAD binds every ciphertext to its context (`vault` / `backup` / file-chunk). |
|1.5| Roll back to an older vault copy | **P** | An attacker who keeps old copies can present a stale one; we can't stop offline file substitution. `.bak` + `updated_at` make it detectable, not impossible. Mitigate with your own versioned backups. |

## 2. Attacker has the vault file **and** your computer (but not the Trezor)

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|2.1| Unlock the vault | **M** | Every unlock needs a physical button press on the device; without it, decryption is impossible. |
|2.2| Ask the device for the key silently | **M** | `ask_on_encrypt`/`ask_on_decrypt` are both set — the device always requires confirmation. |
|2.3| Guess the recovery phrase found on disk | **M** | The phrase is never stored on disk in usable form; only an Argon2id-wrapped blob is. Without the phrase this is 2¹⁹² work (24 words). |

## 3. Attacker has the Trezor (but not the PIN)

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|3.1| Enter PINs until it unlocks | **M** | The device itself rate-limits and wipes after too many wrong PINs (Trezor firmware). |
|3.2| Extract the seed via glitching (older Safe 3, etc.) | **P** | Out of our software's hands, but a **device passphrase** ("25th word") means even a extracted seed can't reproduce the CipherKeyValue key. Enable it. |

## 4. Malware on your machine

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|4.1| Read secrets from the swap file / hibernation image | **M** | Key pages are `VirtualLock`/`mlock`-ed so they never page to disk ([`memlock`](trezor_protector/rust/tp-core/src/memlock.rs)). |
|4.2| Read secrets left in freed memory | **M** | All keys and decrypted buffers are `Zeroizing`/zeroized on drop. |
|4.3| **Scrape the whole vault out of RAM while unlocked** | **P** | We shrink the exposure: keys are locked + zeroized, buffers are transient. But plaintext *must* exist in RAM for the CPU to use it — no user-space program can prevent a process reading its own address space. FDE + not running untrusted code is the real defence. |
|4.4| Screen-scrape / stream the window (RAT) | **P** | Anti-RAT setting excludes the windows from capture (`WDA_EXCLUDEFROMCAPTURE`, implemented on Windows in [`platform.rs`](trezor_protector/rust/tp-gui/src/platform.rs); toggled live from Settings). Defeats screen recording; does **not** defeat a keylogger with input injection or a kernel attacker. |
|4.5| Keylog the PIN | **M** | The PIN is entered as *matrix positions* mapped to a layout shown only on the device screen — captured keystrokes are meaningless without that screen. |
|4.6| Clipboard sniffer / Windows clipboard history | **P** | Copies auto-clear (configurable). If OS clipboard history/sync is on, entries may persist there — prefer **Fill**, and disable history. |
|4.7| Swap our binary for a trojan | **O** | We can't defend our own executable from a machine that's already compromised. Verify release hashes; use OS code-signing/AppLocker. |

## 5. Browser / extension

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|5.1| DOM-based extension clickjacking (DEF CON 33 / VU#516608) | **M** | The extension injects **no UI** into pages; fill is popup-driven only. There is no in-page element to overlay or spoof. |
|5.2| Phishing site triggers autofill | **M** | Fill requires an explicit popup click, checks the tab domain against the entry URL, and warns on mismatch. |
|5.3| Malicious page reads the captured password before you save it | **M** | The save-detection content script only *sends* to the local host; the captured password is never returned to the page or even to the popup. |
|5.4| Rogue site impersonates the native host | **M** | Chrome verifies the extension ID against the host manifest's `allowed_origins`. |
|5.5| Extension writes junk into the vault | **M** | Only `add`/`update_password` can write, and only in an unlocked session — i.e. after a device confirmation. |

## 6. Recovery phrase

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|6.1| Brute-force the phrase | **M** | 24 words ≈ 192 bits; even 12 ≈ 96 bits, and Argon2id (64 MiB, t=3) makes each guess cost ~64 MiB + tens of ms. |
|6.2| Steal the written phrase | **P** | Optional memorized **passphrase** mixed into the KDF: the paper alone then decrypts nothing. |
|6.3| Attach *their* device to *your* vault via recovery | **M** | Recovery only yields the master key; binding to a new Trezor still needs that device to confirm the re-wrap on its own screen. |
|6.4| Tamper with the recovery blob in the file | **M** | It is AES-256-GCM with its own AAD; tampering fails authentication. |

## 7. File encryption

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|7.1| Truncate / append / reorder chunks | **M** | Each chunk's AAD carries its index; the final chunk is marked; trailing data is rejected. |
|7.2| Path traversal via embedded filename | **M** | The restore name is reduced to its basename. |
|7.3| Nonce reuse across a large corpus | **M** | Per-file random 16-byte key (HKDF), so nonce spaces don't collide across files. |
|7.4| Recover a "shredded" file | **P** | Multi-pass overwrite defeats recovery on HDD/NTFS; on SSD/CoW filesystems wear-levelling may keep old blocks — FDE is the only hard guarantee. |

## 8. Supply chain / crypto stack

| # | Attack | Status | Design response |
|---|--------|--------|-----------------|
|8.1| Memory-safety CVE in a C crypto lib (OpenSSL-class) | **M** | Pure-Rust RustCrypto stack, no OpenSSL. `tp-core` is `#![forbid(unsafe_code)]`. |
|8.2| Malicious dependency | **P** | Small, well-known dependency set; `Cargo.lock` pins versions. Audit with `cargo audit` before releases. |

---

## The three "make it impossible" asks — straight answers

- **"Make brute-forcing the vault impossible."** Already the strongest form:
  there is no vault password — the key is on the Trezor. Guessing it means
  guessing AES-256 (2²⁵⁶). The only guessable surface is the *recovery
  phrase*, which is 192-bit + Argon2id — infeasible, not merely hard.

- **"Eliminate the vault being copied to RAM."** Impossible in the absolute:
  the CPU cannot operate on ciphertext. What we do and will keep improving:
  lock key pages against swap, zeroize aggressively, and keep decrypted
  material transient. Full-disk encryption + a clean OS cover the rest.

- **"Protect the app from RAT by hiding the window."** We exclude the
  windows from screen capture, which stops remote **viewing**. A RAT that
  already runs as you can still inject input or read memory — no app can fix
  a fully-owned host. Treat the anti-RAT toggle as one layer, not a cure.
