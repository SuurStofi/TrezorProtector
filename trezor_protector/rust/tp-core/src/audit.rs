//! Vault health audit: weak, reused and stale passwords, plus the SHA-1
//! prefix material for a k-anonymity Have-I-Been-Pwned lookup.
//!
//! The HIBP check never sends the password (or even its full hash) anywhere:
//! only the first 5 hex characters of the SHA-1 leave the machine, and the
//! caller compares the returned suffix list locally.

use std::collections::HashMap;

use sha1::{Digest, Sha1};
use time::{Duration, OffsetDateTime};

use crate::passwords::{entropy_bits, strength_label};
use crate::util::parse_rfc3339;
use crate::vault::Entry;

pub struct Finding {
    pub entry_id: String,
    pub entry_name: String,
    pub kind: FindingKind,
    pub detail: String,
}

#[derive(PartialEq, Eq, Debug)]
pub enum FindingKind {
    WeakPassword,
    ReusedPassword,
    StalePassword,
    MissingTotp,
}

/// Run all local checks over the vault entries.
pub fn audit(entries: &[Entry], stale_after_days: i64) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Weak passwords.
    for e in entries {
        let bits = entropy_bits(&e.password);
        if bits < 60.0 {
            findings.push(Finding {
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                kind: FindingKind::WeakPassword,
                detail: format!("{:.0} bits ({})", bits, strength_label(bits)),
            });
        }
    }

    // Reused passwords (compare within the vault only — nothing leaves it).
    let mut by_password: HashMap<&str, Vec<&Entry>> = HashMap::new();
    for e in entries {
        if !e.password.is_empty() {
            by_password.entry(e.password.as_str()).or_default().push(e);
        }
    }
    for group in by_password.values().filter(|g| g.len() > 1) {
        let names: Vec<&str> = group.iter().map(|e| e.name.as_str()).collect();
        for e in group {
            findings.push(Finding {
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                kind: FindingKind::ReusedPassword,
                detail: format!("same password as: {}", names.join(", ")),
            });
        }
    }

    // Stale passwords.
    let cutoff = OffsetDateTime::now_utc() - Duration::days(stale_after_days);
    for e in entries {
        if let Some(updated) = parse_rfc3339(&e.updated_at) {
            if updated < cutoff {
                findings.push(Finding {
                    entry_id: e.id.clone(),
                    entry_name: e.name.clone(),
                    kind: FindingKind::StalePassword,
                    detail: format!("not changed in over {stale_after_days} days"),
                });
            }
        }
    }

    // Entries with a URL but no stored TOTP — a gentle 2FA nudge.
    for e in entries {
        if e.totp_secret.is_none() && !e.url.is_empty() {
            findings.push(Finding {
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                kind: FindingKind::MissingTotp,
                detail: "no 2FA code stored".into(),
            });
        }
    }

    findings
}

/// SHA-1 of the password split for the HIBP range API:
/// returns (first 5 hex chars, remaining 35 hex chars), both uppercase.
pub fn hibp_parts(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = hex::encode_upper(digest);
    (hex[..5].to_string(), hex[5..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hibp_split_matches_known_sha1() {
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hibp_parts("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn detects_reuse_and_weakness() {
        let a = Entry::new("site-a", "u", "https://a.com", "abc", "");
        let b = Entry::new("site-b", "u", "https://b.com", "abc", "");
        let findings = audit(&[a, b], 365);
        assert!(findings.iter().any(|f| f.kind == FindingKind::ReusedPassword));
        assert!(findings.iter().any(|f| f.kind == FindingKind::WeakPassword));
    }
}
