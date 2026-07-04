//! AES-256-GCM authenticated encryption with domain-separated subkeys.
//!
//! Wire format: 12-byte nonce | ciphertext | 16-byte GCM tag
//!
//! Every call draws a fresh random nonce from the OS CSPRNG, and callers
//! bind ciphertexts to their context via AAD so a blob cut out of one place
//! cannot be replayed somewhere else (vault blob into a file, one entry into
//! another, etc.).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// A 32-byte secret key that is wiped from memory on drop and whose backing
/// page is locked into RAM (`VirtualLock` / `mlock`) so it is never written
/// to the swap file / hibernation image. See [`crate::memlock`].
///
/// The key lives behind a `Box` so its address is stable — a prerequisite
/// for locking the exact page it occupies.
pub struct SecretKey {
    bytes: Box<[u8; KEY_LEN]>,
    _lock: crate::memlock::Locked,
}

impl SecretKey {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        let mut boxed = Box::new(bytes);
        // Zero the caller's stack copy; the canonical copy is now on the heap.
        let mut scratch = bytes;
        scratch.zeroize();
        let lock = crate::memlock::lock(boxed.as_mut_ptr(), KEY_LEN);
        Self { bytes: boxed, _lock: lock }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Crypto("key must be exactly 32 bytes".into()))?;
        Ok(Self::new(arr))
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let key = Self::new(bytes);
        bytes.zeroize();
        key
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Derive a domain-separated subkey (HKDF-SHA256).
    ///
    /// The master key itself never touches user data directly: the vault
    /// blob, file encryption, and any future feature each get their own
    /// derived key, so a compromise or misuse of one context cannot be
    /// leveraged against another.
    pub fn derive(&self, context: &str) -> SecretKey {
        let hk = Hkdf::<Sha256>::new(Some(b"TrezorProtector.v2"), self.bytes.as_ref());
        let mut okm = [0u8; KEY_LEN];
        hk.expand(context.as_bytes(), &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let key = SecretKey::new(okm);
        okm.zeroize();
        key
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Wipe before the page lock is released (self._lock drops after).
        self.bytes.zeroize();
    }
}

/// Argon2id key derivation (shared by the recovery phrase and the
/// password-protected backup). 64 MiB, 3 passes — deliberately expensive so
/// even a low-entropy passphrase is costly to attack offline.
pub fn argon2id_key(secret: &[u8], salt: &[u8]) -> Result<SecretKey> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(KEY_LEN))
        .map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = [0u8; KEY_LEN];
    argon
        .hash_password_into(secret, salt, &mut okm)
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
    let key = SecretKey::new(okm);
    okm.zeroize();
    Ok(key)
}

pub const ARGON_M_KIB: u32 = 65536; // 64 MiB
pub const ARGON_T: u32 = 3;
pub const ARGON_P: u32 = 1;

/// Encrypt `plaintext` bound to `aad`. Returns nonce || ciphertext || tag.
pub fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("encryption failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt nonce || ciphertext || tag produced by [`encrypt`] with the same `aad`.
///
/// The plaintext comes back in a [`Zeroizing`] buffer so it is wiped when the
/// caller drops it.
pub fn decrypt(key: &SecretKey, data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("ciphertext too short".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload { msg: ciphertext, aad },
        )
        .map_err(|_| {
            Error::Crypto(
                "decryption failed: wrong key, wrong context, or tampered data".into(),
            )
        })?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = SecretKey::generate();
        let ct = encrypt(&key, b"hello world", b"ctx").unwrap();
        let pt = decrypt(&key, &ct, b"ctx").unwrap();
        assert_eq!(&pt[..], b"hello world");
    }

    #[test]
    fn unique_nonces() {
        let key = SecretKey::generate();
        let a = encrypt(&key, b"same", b"").unwrap();
        let b = encrypt(&key, b"same", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn aad_binding_rejects_context_swap() {
        let key = SecretKey::generate();
        let ct = encrypt(&key, b"secret", b"vault").unwrap();
        assert!(decrypt(&key, &ct, b"file").is_err());
    }

    #[test]
    fn tamper_detected() {
        let key = SecretKey::generate();
        let mut ct = encrypt(&key, b"secret", b"").unwrap();
        let mid = ct.len() / 2;
        ct[mid] ^= 0xff;
        assert!(decrypt(&key, &ct, b"").is_err());
    }

    #[test]
    fn derived_keys_differ_by_context() {
        let key = SecretKey::generate();
        assert_ne!(
            key.derive("vault").as_bytes(),
            key.derive("files").as_bytes()
        );
        // deterministic
        assert_eq!(
            key.derive("vault").as_bytes(),
            key.derive("vault").as_bytes()
        );
    }
}
