//! Persisted user settings (`~/.trezorprotector/settings.json`).
//!
//! Settings tune the security/convenience trade-off. They are *not* secret
//! — they contain no key material — but several of them (per-operation PIN,
//! lock-on-disconnect) are enforced by the CLI/GUI/host at the point of use.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

fn default_true() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Require a fresh device confirmation for every secret reveal / copy /
    /// fill, not just for the initial unlock.
    pub pin_every_operation: bool,

    /// Lock the vault automatically after this many idle minutes (0 = never).
    pub auto_lock_minutes: u64,

    /// Re-lock (and require a new unlock) as soon as the Trezor is unplugged.
    pub lock_on_disconnect: bool,

    /// Ask to unlock again after the app or extension was manually locked
    /// (vs. staying unlocked within the session).
    pub relock_after_manual_lock: bool,

    /// Anti-RAT mode: exclude the app windows from screen capture / remote
    /// streaming (`WDA_EXCLUDEFROMCAPTURE` on Windows) where supported.
    pub screen_capture_protection: bool,

    /// Default clipboard auto-clear delay, in seconds (0 = never).
    pub clipboard_clear_seconds: u64,

    /// Show generated letter/colour tiles next to entries.
    #[serde(default = "default_true")]
    pub show_site_icons: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            pin_every_operation: false,
            auto_lock_minutes: 5,
            lock_on_disconnect: true,
            relock_after_manual_lock: true,
            screen_capture_protection: false,
            clipboard_clear_seconds: 30,
            show_site_icons: true,
        }
    }
}

impl Settings {
    pub fn default_path() -> PathBuf {
        crate::vault::default_path()
            .parent()
            .map(|p| p.join("settings.json"))
            .unwrap_or_else(|| PathBuf::from("settings.json"))
    }

    /// Load settings, falling back to defaults if the file is missing or
    /// unreadable (a corrupt settings file must never block access to the
    /// vault).
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn load_default() -> Self {
        Self::load(&Self::default_path())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn save_default(&self) -> Result<()> {
        self.save(&Self::default_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("tpset-{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");

        // Missing file → defaults.
        let s = Settings::load(&path);
        assert_eq!(s.auto_lock_minutes, 5);
        assert!(s.lock_on_disconnect);

        let mut s2 = s;
        s2.pin_every_operation = true;
        s2.screen_capture_protection = true;
        s2.save(&path).unwrap();

        let loaded = Settings::load(&path);
        assert!(loaded.pin_every_operation);
        assert!(loaded.screen_capture_protection);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn corrupt_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir().join(format!("tpset-{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let s = Settings::load(&path);
        assert_eq!(s.auto_lock_minutes, 5); // defaulted, not a panic
        std::fs::remove_dir_all(dir).ok();
    }
}
