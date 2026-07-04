//! Seed-phrase recovery — re-bind a vault to a *new* Trezor.
//!
//! The vault's master key is normally wrapped only by the device
//! (CipherKeyValue). If the Trezor is lost or replaced, that wrapping is
//! gone. Recovery adds a *second, independent* wrapping of the same master
//! key, unlocked by a word phrase the user writes down offline:
//!
//! ```text
//! recovery_key = Argon2id( normalize(phrase) || 0x1f || passphrase , salt )
//! wrapped      = AES-256-GCM( recovery_key , master_key , aad="recovery" )
//! ```
//!
//! To recover: derive `recovery_key` from the phrase, decrypt `wrapped` to
//! get the master key, then re-wrap it with the NEW device's CipherKeyValue
//! and overwrite `encrypted_master_key`. The new device confirms the
//! re-wrap with a physical button press.
//!
//! Attack-vector notes (as requested):
//!  * **Brute force.** A 24-word phrase from the 256-word list carries 192
//!    bits of entropy; even a 12-word phrase is 96 bits. Argon2id (64 MiB,
//!    3 passes) makes each guess cost ~tens of milliseconds and ~64 MiB, so
//!    even a weak phrase resists offline attack, and a full-length one is
//!    infeasible regardless.
//!  * **Coercion / theft of the written phrase.** The optional extra
//!    *passphrase* (never written down, memorized) is mixed into the KDF —
//!    the paper phrase alone then decrypts nothing. This is the same
//!    "25th word" idea Trezor uses for the seed.
//!  * **Spoofing a new device.** Recovery only yields the master key;
//!    binding it to a new Trezor still requires that device to confirm the
//!    CipherKeyValue operation on its own screen, so an attacker cannot
//!    silently attach their device to your vault file.
//!  * **The phrase is as sensitive as the seed** — store it offline, never
//!    photograph or type it into anything but this tool.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, SecretKey};
use crate::error::{Error, Result};
use crate::passwords::wordlist;

const RECOVERY_AAD: &[u8] = b"TrezorProtector.recovery.v1";
const DEFAULT_WORDS: usize = 24;

/// Persisted recovery material (safe to store in the vault header — it is
/// useless without the phrase).
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryData {
    pub words: usize,
    pub salt: String,    // hex
    pub wrapped: String, // hex, AES-256-GCM(master_key)
}

/// Generate a fresh recovery phrase (space-separated words).
pub fn generate_phrase(words: usize) -> Result<Zeroizing<String>> {
    let words = if words == 0 { DEFAULT_WORDS } else { words };
    if !(12..=48).contains(&words) {
        return Err(Error::InvalidInput("phrase length must be 12–48 words".into()));
    }
    let list = wordlist();
    let mut rng = rand::rngs::OsRng;
    use rand::Rng;
    let picked: Vec<&str> = (0..words)
        .map(|_| list[rng.gen_range(0..list.len())])
        .collect();
    Ok(Zeroizing::new(picked.join(" ")))
}

/// Collapse whitespace and lowercase so that transcription differences
/// (extra spaces, capitalisation, line breaks) do not change the key.
fn normalize(phrase: &str) -> Zeroizing<String> {
    Zeroizing::new(
        phrase
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn derive_key(phrase: &str, passphrase: &str, salt: &[u8]) -> Result<SecretKey> {
    let norm = normalize(phrase);
    if norm.is_empty() {
        return Err(Error::InvalidInput("recovery phrase is empty".into()));
    }
    let mut material = Zeroizing::new(Vec::with_capacity(norm.len() + 1 + passphrase.len()));
    material.extend_from_slice(norm.as_bytes());
    material.push(0x1f); // separator so phrase+pass can't be ambiguous
    material.extend_from_slice(passphrase.as_bytes());
    crypto::argon2id_key(&material, salt)
}

/// Wrap `master` under the phrase (+ optional passphrase). `words` is stored
/// only to remind the user how long their phrase should be.
pub fn wrap(
    phrase: &str,
    passphrase: &str,
    words: usize,
    master: &SecretKey,
) -> Result<RecoveryData> {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key = derive_key(phrase, passphrase, &salt)?;
    let wrapped = crypto::encrypt(&key, master.as_bytes(), RECOVERY_AAD)?;
    Ok(RecoveryData {
        words,
        salt: hex::encode(salt),
        wrapped: hex::encode(wrapped),
    })
}

/// Recover the master key from the phrase (+ optional passphrase).
pub fn unwrap(phrase: &str, passphrase: &str, data: &RecoveryData) -> Result<SecretKey> {
    let salt = hex::decode(&data.salt)
        .map_err(|_| Error::InvalidInput("corrupt recovery salt".into()))?;
    let wrapped = hex::decode(&data.wrapped)
        .map_err(|_| Error::InvalidInput("corrupt recovery blob".into()))?;
    let key = derive_key(phrase, passphrase, &salt)?;
    let master = crypto::decrypt(&key, &wrapped, RECOVERY_AAD)
        .map_err(|_| Error::Crypto("wrong recovery phrase or passphrase".into()))?;
    SecretKey::from_slice(&master)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_has_requested_length() {
        let p = generate_phrase(24).unwrap();
        assert_eq!(p.split_whitespace().count(), 24);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let master = SecretKey::generate();
        let phrase = generate_phrase(24).unwrap();
        let data = wrap(&phrase, "", 24, &master).unwrap();
        let recovered = unwrap(&phrase, "", &data).unwrap();
        assert_eq!(recovered.as_bytes(), master.as_bytes());
    }

    #[test]
    fn normalization_is_forgiving() {
        let master = SecretKey::generate();
        let data = wrap("Copper  Lantern\nOrbit", "", 3, &master).unwrap();
        // Different spacing / case must still recover.
        assert_eq!(
            unwrap("copper lantern orbit", "", &data).unwrap().as_bytes(),
            master.as_bytes()
        );
    }

    #[test]
    fn passphrase_is_required_when_set() {
        let master = SecretKey::generate();
        let phrase = generate_phrase(12).unwrap();
        let data = wrap(&phrase, "extra-secret", 12, &master).unwrap();
        // Right phrase, missing passphrase → fails.
        assert!(unwrap(&phrase, "", &data).is_err());
        // Right phrase + passphrase → succeeds.
        assert_eq!(
            unwrap(&phrase, "extra-secret", &data).unwrap().as_bytes(),
            master.as_bytes()
        );
    }

    #[test]
    fn wrong_phrase_rejected() {
        let master = SecretKey::generate();
        let data = wrap(&generate_phrase(24).unwrap(), "", 24, &master).unwrap();
        assert!(unwrap(&generate_phrase(24).unwrap(), "", &data).is_err());
    }
}
