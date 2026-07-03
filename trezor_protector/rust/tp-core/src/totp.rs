//! RFC 6238 TOTP (time-based one-time passwords).
//!
//! Storing the TOTP secret next to the password weakens "something you have"
//! to "something in the vault" — but here the vault itself is unlocked by a
//! hardware device, so codes are only available after a physical
//! confirmation. Convenient *and* still two-factor against remote attackers.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

pub struct Code {
    pub code: String,
    /// Seconds until this code expires.
    pub seconds_remaining: u64,
}

impl Totp {
    /// Build from a base32 secret (the standard "JBSWY3DP…" form, spaces and
    /// case ignored) with default parameters (SHA-1, 6 digits, 30 s).
    pub fn from_base32(secret: &str) -> Result<Self> {
        let cleaned: String = secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &cleaned))
            .ok_or_else(|| Error::InvalidInput("invalid base32 TOTP secret".into()))?;
        if bytes.is_empty() {
            return Err(Error::InvalidInput("empty TOTP secret".into()));
        }
        Ok(Self { secret: bytes, digits: 6, period: 30, algorithm: Algorithm::Sha1 })
    }

    /// Parse an `otpauth://totp/...` URI as produced by QR codes.
    pub fn from_otpauth(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or_else(|| Error::InvalidInput("not an otpauth://totp/ URI".into()))?;
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

        let mut secret = None;
        let mut totp_digits = 6u32;
        let mut period = 30u64;
        let mut algorithm = Algorithm::Sha1;

        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v.to_string()),
                "digits" => {
                    totp_digits = v
                        .parse()
                        .map_err(|_| Error::InvalidInput("bad digits parameter".into()))?
                }
                "period" => {
                    period = v
                        .parse()
                        .map_err(|_| Error::InvalidInput("bad period parameter".into()))?
                }
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => {
                            return Err(Error::InvalidInput(format!(
                                "unsupported algorithm {other}"
                            )))
                        }
                    }
                }
                _ => {}
            }
        }

        let secret =
            secret.ok_or_else(|| Error::InvalidInput("otpauth URI missing secret".into()))?;
        let mut totp = Self::from_base32(&secret)?;
        if !(6..=8).contains(&totp_digits) {
            return Err(Error::InvalidInput("digits must be 6-8".into()));
        }
        if !(15..=120).contains(&period) {
            return Err(Error::InvalidInput("period must be 15-120 seconds".into()));
        }
        totp.digits = totp_digits;
        totp.period = period;
        totp.algorithm = algorithm;
        Ok(totp)
    }

    /// Current code plus its remaining validity.
    pub fn now(&self) -> Result<Code> {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Crypto("system clock before 1970".into()))?
            .as_secs();
        Ok(Code {
            code: self.at(unix),
            seconds_remaining: self.period - (unix % self.period),
        })
    }

    /// Code for an arbitrary unix timestamp (used by tests / RFC vectors).
    pub fn at(&self, unix_seconds: u64) -> String {
        let counter = (unix_seconds / self.period).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac_digest(
                <Hmac<Sha1> as Mac>::new_from_slice(&self.secret),
                &counter,
            ),
            Algorithm::Sha256 => hmac_digest(
                <Hmac<Sha256> as Mac>::new_from_slice(&self.secret),
                &counter,
            ),
            Algorithm::Sha512 => hmac_digest(
                <Hmac<Sha512> as Mac>::new_from_slice(&self.secret),
                &counter,
            ),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }
}

fn hmac_digest<M: Mac>(
    mac: std::result::Result<M, hmac::digest::InvalidLength>,
    message: &[u8],
) -> Vec<u8> {
    let mut mac = mac.expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

impl Drop for Totp {
    fn drop(&mut self) {
        self.secret.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vectors (SHA-1 secret "12345678901234567890").
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret_b32 =
            base32::encode(base32::Alphabet::Rfc4648 { padding: false }, b"12345678901234567890");
        let mut totp = Totp::from_base32(&secret_b32).unwrap();
        totp.digits = 8;
        assert_eq!(totp.at(59), "94287082");
        assert_eq!(totp.at(1111111109), "07081804");
        assert_eq!(totp.at(1234567890), "89005924");
        assert_eq!(totp.at(20000000000), "65353130");
    }

    #[test]
    fn otpauth_parsing() {
        let t = Totp::from_otpauth(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.algorithm, Algorithm::Sha1);
    }

    #[test]
    fn lowercase_and_spaces_accepted() {
        assert!(Totp::from_base32("jbsw y3dp ehpk 3pxp").is_ok());
    }

    #[test]
    fn garbage_rejected() {
        assert!(Totp::from_base32("not!base32@@").is_err());
        assert!(Totp::from_otpauth("https://example.com").is_err());
    }
}
