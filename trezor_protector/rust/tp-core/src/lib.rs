//! TrezorProtector core library.
//!
//! Everything security-critical lives here so the CLI, the native-messaging
//! host and any future front end share one audited implementation:
//!
//! * [`crypto`] — AES-256-GCM with AAD context binding + HKDF subkeys
//! * [`vault`] — the encrypted vault file (v2 format, v1 migration)
//! * [`files`] — streaming file encryption (TPENC2, legacy TPENC1 reads)
//! * [`passwords`] — generation and strength estimation
//! * [`totp`] — RFC 6238 one-time codes
//! * [`audit`] — weak/reused/stale password detection, HIBP k-anonymity parts
//! * [`trezor`] — hardware device access (CipherKeyValue key wrapping)

#![forbid(unsafe_code)]

pub mod audit;
pub mod crypto;
pub mod error;
pub mod files;
pub mod memlock;
pub mod passwords;
pub mod recovery;
pub mod settings;
pub mod totp;
pub mod trezor;
pub mod util;
pub mod vault;

pub use error::{Error, Result};
