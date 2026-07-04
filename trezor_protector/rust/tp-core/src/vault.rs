//! Vault v2 — the single encrypted file on disk.
//!
//! On-disk layout (JSON):
//! ```json
//! {
//!   "version": 2,
//!   "created_at": "<rfc3339>",
//!   "updated_at": "<rfc3339>",
//!   "key_protection": "trezor-cipherkeyvalue m/10016'/0'",
//!   "encrypted_master_key": "<hex, 32 bytes wrapped by the Trezor>",
//!   "data": "<hex, AES-256-GCM blob of the full entry list>"
//! }
//! ```
//!
//! Differences from v1 (the Python format), all security-motivated:
//!  * **No plaintext metadata.** v1 stored entry names, usernames and URLs in
//!    the clear; v2 encrypts the entire entry list as one blob, so the file
//!    leaks nothing but its size.
//!  * **Whole-vault integrity.** One GCM tag covers the complete list — an
//!    attacker with file access can no longer silently delete, duplicate or
//!    reorder individual entries (v1 authenticated each blob separately).
//!  * **AAD context binding** stops ciphertext transplanted from files or
//!    backups from being accepted as vault data.
//!  * **Atomic writes + automatic `.bak`** so a crash mid-save cannot destroy
//!    the vault.
//!  * The master key is used only through HKDF-derived subkeys.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, SecretKey};
use crate::error::{Error, Result};
use crate::util::{new_id, now_rfc3339};

const VAULT_AAD: &[u8] = b"TrezorProtector.vault.v2";
const BACKUP_AAD: &[u8] = b"TrezorProtector.backup.v1";
/// HKDF context for the vault subkey.
const VAULT_KEY_CONTEXT: &str = "vault-v2";

pub const KEY_PROTECTION: &str = "trezor-cipherkeyvalue m/10016'/0'";

/// Maximum password-history items kept per entry.
const HISTORY_CAP: usize = 10;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HistoryItem {
    pub password: String,
    pub replaced_at: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
    pub password: String,
    #[serde(default)]
    pub notes: String,
    /// Base32 TOTP secret (RFC 6238), if two-factor codes are stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryItem>,
    pub created_at: String,
    pub updated_at: String,
}

impl Entry {
    pub fn new(name: &str, username: &str, url: &str, password: &str, notes: &str) -> Self {
        let now = now_rfc3339();
        Self {
            id: new_id(),
            name: name.into(),
            username: username.into(),
            url: url.into(),
            password: password.into(),
            notes: notes.into(),
            totp_secret: None,
            tags: Vec::new(),
            history: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    fn matches(&self, q: &str) -> bool {
        let q = q.to_lowercase();
        self.name.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self.url.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
    }
}

// ---------------------------------------------------------------------------
// On-disk header
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    created_at: String,
    updated_at: String,
    key_protection: String,
    encrypted_master_key: String,
    data: String,
    /// Optional second wrapping of the master key under a recovery phrase,
    /// enabling re-binding to a new Trezor. See [`crate::recovery`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<crate::recovery::RecoveryData>,
}

pub fn default_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".trezorprotector").join("vault.json")
}

// ---------------------------------------------------------------------------
// Locked vault
// ---------------------------------------------------------------------------

pub struct Vault {
    path: PathBuf,
    header: Header,
}

impl Vault {
    /// Create a brand-new vault with an empty entry list.
    pub fn create(path: &Path, wrapped_master_key: &[u8], master: &SecretKey) -> Result<Vault> {
        let now = now_rfc3339();
        let mut header = Header {
            version: 2,
            created_at: now.clone(),
            updated_at: now,
            key_protection: KEY_PROTECTION.into(),
            encrypted_master_key: hex::encode(wrapped_master_key),
            data: String::new(),
            recovery: None,
        };
        header.data = seal_entries(&[], master)?;
        let vault = Vault { path: path.to_path_buf(), header };
        vault.write_to_disk()?;
        Ok(vault)
    }

    pub fn load(path: &Path) -> Result<Vault> {
        let raw = fs::read_to_string(path).map_err(|e| {
            Error::Vault(format!(
                "cannot read vault at {}: {e}\nRun `tp init` to create one.",
                path.display()
            ))
        })?;
        // Detect the legacy Python v1 layout and point users at `tp migrate`.
        let probe: serde_json::Value = serde_json::from_str(&raw)?;
        match probe.get("version").and_then(|v| v.as_u64()) {
            Some(2) => {}
            Some(1) => {
                return Err(Error::Vault(
                    "this is a v1 (Python) vault — run `tp migrate` to upgrade it".into(),
                ))
            }
            other => {
                return Err(Error::Vault(format!(
                    "unsupported vault version {other:?}"
                )))
            }
        }
        let header: Header = serde_json::from_str(&raw)?;
        Ok(Vault { path: path.to_path_buf(), header })
    }

    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn wrapped_master_key(&self) -> Result<Vec<u8>> {
        hex::decode(&self.header.encrypted_master_key)
            .map_err(|_| Error::Vault("corrupt encrypted_master_key field".into()))
    }

    /// Whether a recovery phrase has been set up for this vault.
    pub fn has_recovery(&self) -> bool {
        self.header.recovery.is_some()
    }

    /// Recover the master key from the recovery phrase (used when the Trezor
    /// is lost). The caller then re-binds it to a new device via
    /// [`Vault::rebind`].
    pub fn recover_master_key(&self, phrase: &str, passphrase: &str) -> Result<SecretKey> {
        let data = self
            .header
            .recovery
            .as_ref()
            .ok_or_else(|| Error::Vault("no recovery phrase set up for this vault".into()))?;
        crate::recovery::unwrap(phrase, passphrase, data)
    }

    /// Overwrite the device wrapping with `new_wrapped` (the master key
    /// re-encrypted by a new Trezor) and persist. The vault data itself is
    /// untouched — the master key is unchanged, only its device wrapping.
    pub fn rebind(&mut self, new_wrapped: &[u8]) -> Result<()> {
        self.header.encrypted_master_key = hex::encode(new_wrapped);
        self.header.updated_at = now_rfc3339();
        self.write_to_disk()
    }

    /// Decrypt the entry list with the master key returned by the Trezor.
    pub fn unlock(self, master: &SecretKey) -> Result<UnlockedVault> {
        let blob = hex::decode(&self.header.data)
            .map_err(|_| Error::Vault("corrupt data field".into()))?;
        let vault_key = master.derive(VAULT_KEY_CONTEXT);
        let plaintext = crypto::decrypt(&vault_key, &blob, VAULT_AAD).map_err(|_| {
            Error::Vault(
                "cannot decrypt vault: wrong device/passphrase or tampered file".into(),
            )
        })?;
        let entries: Vec<Entry> = serde_json::from_slice(&plaintext)?;
        Ok(UnlockedVault { vault: self, entries, vault_key })
    }

    fn write_to_disk(&self) -> Result<()> {
        atomic_write_json(&self.path, &self.header)
    }
}

/// Last-modified time of a vault file, for cheap cross-process change
/// detection (the extension host and the desktop app share one file).
pub fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

// ---------------------------------------------------------------------------
// Unlocked vault
// ---------------------------------------------------------------------------

pub struct UnlockedVault {
    vault: Vault,
    entries: Vec<Entry>,
    vault_key: SecretKey,
}

pub struct EntryPatch {
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}

impl EntryPatch {
    pub fn empty() -> Self {
        Self {
            name: None,
            username: None,
            url: None,
            password: None,
            notes: None,
            totp_secret: None,
            tags: None,
        }
    }
}

impl UnlockedVault {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn path(&self) -> &Path {
        &self.vault.path
    }

    /// Re-read the vault file from disk and re-decrypt it with the key we
    /// already hold — no device interaction needed. Used to pick up writes
    /// made by another process (e.g. the browser extension saving a
    /// password while the desktop app is open).
    pub fn reload(&mut self) -> Result<()> {
        let raw = fs::read_to_string(&self.vault.path)?;
        let header: Header = serde_json::from_str(&raw)?;
        let blob = hex::decode(&header.data)
            .map_err(|_| Error::Vault("corrupt data field".into()))?;
        let plaintext = crypto::decrypt(&self.vault_key, &blob, VAULT_AAD)
            .map_err(|_| Error::Vault("cannot re-decrypt vault after external change".into()))?;
        self.entries = serde_json::from_slice(&plaintext)?;
        self.vault.header = header;
        Ok(())
    }

    pub fn find(&self, query: &str) -> Vec<&Entry> {
        if query.is_empty() {
            return self.entries.iter().collect();
        }
        self.entries.iter().filter(|e| e.matches(query)).collect()
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn add(&mut self, entry: Entry) -> Result<String> {
        let id = entry.id.clone();
        self.entries.push(entry);
        self.save()?;
        Ok(id)
    }

    pub fn update(&mut self, id: &str, patch: EntryPatch) -> Result<()> {
        let now = now_rfc3339();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;

        if let Some(name) = patch.name {
            entry.name = name;
        }
        if let Some(username) = patch.username {
            entry.username = username;
        }
        if let Some(url) = patch.url {
            entry.url = url;
        }
        if let Some(password) = patch.password {
            if password != entry.password {
                entry.history.insert(
                    0,
                    HistoryItem {
                        password: std::mem::take(&mut entry.password),
                        replaced_at: now.clone(),
                    },
                );
                entry.history.truncate(HISTORY_CAP);
                entry.password = password;
            }
        }
        if let Some(notes) = patch.notes {
            entry.notes = notes;
        }
        if let Some(totp) = patch.totp_secret {
            entry.totp_secret = totp;
        }
        if let Some(tags) = patch.tags {
            entry.tags = tags;
        }
        entry.updated_at = now;
        self.save()
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() == before {
            return Err(Error::NotFound(format!("entry {id}")));
        }
        self.save()
    }

    /// Set up (or replace) the recovery phrase. `master` is the unwrapped
    /// master key obtained at unlock time; it is wrapped a second time under
    /// the phrase so a new Trezor can later be bound to this vault.
    pub fn set_recovery(
        &mut self,
        master: &SecretKey,
        phrase: &str,
        passphrase: &str,
        words: usize,
    ) -> Result<()> {
        let data = crate::recovery::wrap(phrase, passphrase, words, master)?;
        self.vault.header.recovery = Some(data);
        self.vault.header.updated_at = now_rfc3339();
        self.vault.write_to_disk()
    }

    pub fn remove_recovery(&mut self) -> Result<()> {
        self.vault.header.recovery = None;
        self.vault.header.updated_at = now_rfc3339();
        self.vault.write_to_disk()
    }

    pub fn has_recovery(&self) -> bool {
        self.vault.has_recovery()
    }

    /// Re-encrypt the entry list and write the vault atomically.
    pub fn save(&mut self) -> Result<()> {
        self.vault.header.data = seal_with_key(&self.entries, &self.vault_key)?;
        self.vault.header.updated_at = now_rfc3339();
        self.vault.write_to_disk()
    }

    /// Re-wrap the vault under a brand-new master key (key rotation).
    ///
    /// `new_wrapped` must be the Trezor-wrapped form of `new_master`.
    pub fn rotate_key(&mut self, new_master: &SecretKey, new_wrapped: &[u8]) -> Result<()> {
        self.vault.header.encrypted_master_key = hex::encode(new_wrapped);
        self.vault_key = new_master.derive(VAULT_KEY_CONTEXT);
        self.save()
    }

    // -- Trezor-independent encrypted backup --------------------------------

    /// Export every entry into a password-protected backup file (Argon2id +
    /// AES-256-GCM). This is the disaster-recovery path if the Trezor is
    /// lost or destroyed.
    pub fn export_backup(&self, path: &Path, password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(Error::InvalidInput(
                "backup password must be at least 8 characters".into(),
            ));
        }
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let key = argon2_key(password, &salt)?;
        let plaintext = serde_json::to_vec(&self.entries)?;
        let blob = crypto::encrypt(&key, &plaintext, BACKUP_AAD)?;

        let backup = serde_json::json!({
            "format": "tpbackup-v1",
            "created_at": now_rfc3339(),
            "kdf": { "algo": "argon2id", "m_kib": ARGON_M_KIB, "t": ARGON_T, "p": ARGON_P,
                     "salt": hex::encode(salt) },
            "data": hex::encode(blob),
        });
        atomic_write_json(path, &backup)
    }

    /// Import entries from a backup file. Entries whose id already exists
    /// are skipped unless the backup copy is newer.
    pub fn import_backup(&mut self, path: &Path, password: &str) -> Result<(usize, usize)> {
        let entries = read_backup(path, password)?;
        let mut added = 0;
        let mut updated = 0;
        for incoming in entries {
            match self.entries.iter_mut().find(|e| e.id == incoming.id) {
                Some(existing) => {
                    if incoming.updated_at > existing.updated_at {
                        *existing = incoming;
                        updated += 1;
                    }
                }
                None => {
                    self.entries.push(incoming);
                    added += 1;
                }
            }
        }
        self.save()?;
        Ok((added, updated))
    }
}

/// Decrypt a `tpbackup-v1` file without needing a vault or Trezor.
pub fn read_backup(path: &Path, password: &str) -> Result<Vec<Entry>> {
    let raw = fs::read_to_string(path)?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    if doc.get("format").and_then(|f| f.as_str()) != Some("tpbackup-v1") {
        return Err(Error::InvalidInput("not a tpbackup-v1 file".into()));
    }
    let salt = hex::decode(
        doc.pointer("/kdf/salt")
            .and_then(|s| s.as_str())
            .ok_or_else(|| Error::InvalidInput("backup missing KDF salt".into()))?,
    )
    .map_err(|_| Error::InvalidInput("corrupt KDF salt".into()))?;
    let blob = hex::decode(
        doc.get("data")
            .and_then(|d| d.as_str())
            .ok_or_else(|| Error::InvalidInput("backup missing data".into()))?,
    )
    .map_err(|_| Error::InvalidInput("corrupt backup data".into()))?;

    let key = argon2_key(password, &salt)?;
    let plaintext = crypto::decrypt(&key, &blob, BACKUP_AAD)
        .map_err(|_| Error::Crypto("wrong backup password or corrupt file".into()))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

// ---------------------------------------------------------------------------
// v1 (Python) migration
// ---------------------------------------------------------------------------

/// Read a legacy Python-format vault and return its wrapped master key plus
/// the decrypted entries (the caller supplies the unwrapped master key,
/// which is the same for v1 and v2 vaults).
pub fn read_v1_entries(path: &Path, master: &SecretKey) -> Result<Vec<Entry>> {
    #[derive(Deserialize)]
    struct V1Entry {
        id: String,
        name: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        url: String,
        encrypted_data: String,
        #[serde(default)]
        created_at: String,
        #[serde(default)]
        updated_at: String,
    }
    #[derive(Deserialize)]
    struct V1Vault {
        version: u32,
        passwords: Vec<V1Entry>,
    }

    let raw = fs::read_to_string(path)?;
    let v1: V1Vault = serde_json::from_str(&raw)?;
    if v1.version != 1 {
        return Err(Error::Vault(format!(
            "expected a v1 vault, found version {}",
            v1.version
        )));
    }

    let mut entries = Vec::with_capacity(v1.passwords.len());
    for p in v1.passwords {
        let blob = hex::decode(&p.encrypted_data)
            .map_err(|_| Error::Vault(format!("corrupt entry blob for '{}'", p.name)))?;
        // v1 encrypted per-entry with the *raw* master key and no AAD.
        let plaintext = crypto::decrypt(master, &blob, b"")
            .map_err(|_| Error::Vault(format!("cannot decrypt v1 entry '{}'", p.name)))?;
        #[derive(Deserialize)]
        struct V1Data {
            password: String,
            #[serde(default)]
            notes: String,
        }
        let data: V1Data = serde_json::from_slice(&plaintext)?;
        let now = now_rfc3339();
        entries.push(Entry {
            id: p.id,
            name: p.name,
            username: p.username,
            url: p.url,
            password: data.password,
            notes: data.notes,
            totp_secret: None,
            tags: Vec::new(),
            history: Vec::new(),
            created_at: if p.created_at.is_empty() { now.clone() } else { p.created_at },
            updated_at: if p.updated_at.is_empty() { now } else { p.updated_at },
        });
    }
    Ok(entries)
}

/// Read just the wrapped master key from a v1 vault file.
pub fn read_v1_wrapped_key(path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    let hex_key = doc
        .get("encrypted_master_key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::Vault("v1 vault missing encrypted_master_key".into()))?;
    hex::decode(hex_key).map_err(|_| Error::Vault("corrupt v1 master key".into()))
}

/// Build a v2 vault from migrated v1 contents.
pub fn create_from_entries(
    path: &Path,
    wrapped_master_key: &[u8],
    master: &SecretKey,
    entries: Vec<Entry>,
) -> Result<()> {
    let now = now_rfc3339();
    let header = Header {
        version: 2,
        created_at: now.clone(),
        updated_at: now,
        key_protection: KEY_PROTECTION.into(),
        encrypted_master_key: hex::encode(wrapped_master_key),
        data: seal_entries(&entries, master)?,
        recovery: None,
    };
    atomic_write_json(path, &header)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn argon2_key(password: &str, salt: &[u8]) -> Result<SecretKey> {
    crypto::argon2id_key(password.as_bytes(), salt)
}

// Re-exported for the backup header so the on-disk KDF metadata stays in sync.
const ARGON_M_KIB: u32 = crypto::ARGON_M_KIB;
const ARGON_T: u32 = crypto::ARGON_T;
const ARGON_P: u32 = crypto::ARGON_P;

fn seal_entries(entries: &[Entry], master: &SecretKey) -> Result<String> {
    seal_with_key(entries, &master.derive(VAULT_KEY_CONTEXT))
}

fn seal_with_key(entries: &[Entry], vault_key: &SecretKey) -> Result<String> {
    let plaintext = serde_json::to_vec(entries)?;
    let blob = crypto::encrypt(vault_key, &plaintext, VAULT_AAD)?;
    Ok(hex::encode(blob))
}

/// Write JSON atomically: temp file in the same directory, back up the old
/// file, then rename over the target. Restrictive permissions on Unix.
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_string_pretty(value)?;

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut fh = opts.open(&tmp)?;
        fh.write_all(body.as_bytes())?;
        fh.sync_all()?;
    }

    if path.exists() {
        let bak = path.with_extension("json.bak");
        fs::copy(path, &bak)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tpvault-test-{}", new_id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_unlock_roundtrip() {
        let dir = tmpdir();
        let path = dir.join("vault.json");
        let master = SecretKey::generate();
        let wrapped = vec![0u8; 32]; // stand-in for the Trezor-wrapped key

        Vault::create(&path, &wrapped, &master).unwrap();
        let mut unlocked = Vault::load(&path).unwrap().unlock(&master).unwrap();
        assert!(unlocked.entries().is_empty());

        let id = unlocked
            .add(Entry::new("github", "alice", "https://github.com", "hunter2", ""))
            .unwrap();
        drop(unlocked);

        let unlocked = Vault::load(&path).unwrap().unlock(&master).unwrap();
        assert_eq!(unlocked.entries().len(), 1);
        assert_eq!(unlocked.get(&id).unwrap().password, "hunter2");
        // backup file created by the second save
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tmpdir();
        let path = dir.join("vault.json");
        let master = SecretKey::generate();
        Vault::create(&path, &[0u8; 32], &master).unwrap();
        let other = SecretKey::generate();
        assert!(Vault::load(&path).unwrap().unlock(&other).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reload_picks_up_external_writes() {
        // Simulates the extension host writing while the app holds the vault.
        let dir = tmpdir();
        let path = dir.join("vault.json");
        let master = SecretKey::generate();
        Vault::create(&path, &[0u8; 32], &master).unwrap();

        let mut app_view = Vault::load(&path).unwrap().unlock(&master).unwrap();
        assert!(app_view.entries().is_empty());

        // Another process opens, adds an entry, and writes.
        let mut host_view = Vault::load(&path).unwrap().unlock(&master).unwrap();
        host_view.add(Entry::new("bank", "me", "https://bank.com", "pw", "")).unwrap();
        drop(host_view);

        // Stale until reload; fresh after.
        assert!(app_view.entries().is_empty());
        app_view.reload().unwrap();
        assert_eq!(app_view.entries().len(), 1);
        assert_eq!(app_view.entries()[0].name, "bank");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn password_update_keeps_history() {
        let dir = tmpdir();
        let path = dir.join("vault.json");
        let master = SecretKey::generate();
        Vault::create(&path, &[0u8; 32], &master).unwrap();
        let mut v = Vault::load(&path).unwrap().unlock(&master).unwrap();
        let id = v.add(Entry::new("x", "u", "", "old-pw", "")).unwrap();

        let mut patch = EntryPatch::empty();
        patch.password = Some("new-pw".into());
        v.update(&id, patch).unwrap();

        let e = v.get(&id).unwrap();
        assert_eq!(e.password, "new-pw");
        assert_eq!(e.history.len(), 1);
        assert_eq!(e.history[0].password, "old-pw");
        fs::remove_dir_all(dir).ok();
    }

    /// Fixture produced by the original Python implementation
    /// (cryptography.AESGCM, master key = bytes 0x00..0x1f) — proves the
    /// Rust migration path decrypts real v1 vaults byte-for-byte.
    #[test]
    fn python_v1_vault_migrates() {
        let v1_json = r#"{"version": 1, "created_at": "2025-01-01T00:00:00+00:00",
            "encrypted_master_key": "2222222222222222222222222222222222222222222222222222222222222222",
            "passwords": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "github.com",
                "username": "alice", "url": "https://github.com",
                "encrypted_data": "eca2ebe1f46a4f7b7d4f9d99f6a62ce952804ff6c68c1361516645543be8e56ed96c6521bf826d957e9409bdabe756d0080bd9e0de0b938a18996ec435cf01a86142c8b4646c7c",
                "created_at": "2025-01-01T00:00:00+00:00",
                "updated_at": "2025-01-02T00:00:00+00:00"}]}"#;
        let dir = tmpdir();
        let path = dir.join("v1.json");
        fs::write(&path, v1_json).unwrap();

        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let master = SecretKey::new(key);

        assert_eq!(read_v1_wrapped_key(&path).unwrap(), vec![0x22u8; 32]);
        let entries = read_v1_entries(&path, &master).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "github.com");
        assert_eq!(entries[0].username, "alice");
        assert_eq!(entries[0].password, "hunter2");
        assert_eq!(entries[0].notes, "my note");

        // And the migrated vault opens as v2.
        create_from_entries(&dir.join("v2.json"), &[0x22u8; 32], &master, entries).unwrap();
        let v2 = Vault::load(&dir.join("v2.json")).unwrap().unlock(&master).unwrap();
        assert_eq!(v2.entries()[0].password, "hunter2");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backup_roundtrip() {
        let dir = tmpdir();
        let path = dir.join("vault.json");
        let master = SecretKey::generate();
        Vault::create(&path, &[0u8; 32], &master).unwrap();
        let mut v = Vault::load(&path).unwrap().unlock(&master).unwrap();
        v.add(Entry::new("site", "bob", "", "s3cret", "")).unwrap();

        let backup = dir.join("backup.tpbackup");
        v.export_backup(&backup, "correct horse battery").unwrap();

        let entries = read_backup(&backup, "correct horse battery").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password, "s3cret");
        assert!(read_backup(&backup, "wrong password!").is_err());
        fs::remove_dir_all(dir).ok();
    }
}
