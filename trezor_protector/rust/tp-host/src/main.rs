//! TrezorProtector native messaging host.
//!
//! Chrome launches this binary and speaks the native-messaging protocol over
//! stdio: every message is a 4-byte native-endian length followed by JSON.
//!
//! Security model:
//!  * The vault master key exists only in this process, never in the
//!    browser. The extension asks for one secret at a time, on explicit
//!    user action.
//!  * `list` returns metadata only — passwords and TOTP secrets are never
//!    included in bulk responses.
//!  * Auto-lock drops (and zeroizes) all key material after an idle period
//!    (default 5 minutes) and when the browser disconnects (stdin EOF ends
//!    the process).
//!  * Trezor PIN entry is relayed as *matrix positions*: the digits the
//!    user clicks map to the scrambled layout shown on the device screen,
//!    so neither the browser nor this process ever learns the real PIN.
//!
//! Also provides `install` / `uninstall` subcommands that register the host
//! manifest for Chrome/Edge (per-user, no admin rights needed).

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use tp_core::passwords::{self, GenerateOptions};
use tp_core::totp::Totp;
use tp_core::trezor::{Interaction, TrezorManager};
use tp_core::vault::{self, UnlockedVault, Vault};
use tp_core::{Error, Result};

const HOST_NAME: &str = "com.trezorprotector";
const DEFAULT_AUTOLOCK: Duration = Duration::from_secs(5 * 60);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("install") => match install(&args[2..]) {
            Ok(msg) => println!("{msg}"),
            Err(e) => {
                eprintln!("install failed: {e}");
                std::process::exit(1);
            }
        },
        Some("uninstall") => match uninstall() {
            Ok(()) => println!("Native messaging host unregistered."),
            Err(e) => {
                eprintln!("uninstall failed: {e}");
                std::process::exit(1);
            }
        },
        // Chrome invokes the host with the extension origin as an argument.
        _ => host_loop(),
    }
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

fn read_msg() -> Option<Value> {
    let mut stdin = std::io::stdin().lock();
    let mut len_bytes = [0u8; 4];
    if stdin.read_exact(&mut len_bytes).is_err() {
        return None; // browser closed the pipe
    }
    let len = u32::from_ne_bytes(len_bytes) as usize;
    if len == 0 || len > 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; len];
    stdin.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn write_msg(value: &Value) {
    let body = serde_json::to_vec(value).expect("JSON serialization cannot fail");
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(&(body.len() as u32).to_ne_bytes());
    let _ = stdout.write_all(&body);
    let _ = stdout.flush();
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

struct Session {
    unlocked: Option<UnlockedVault>,
    last_activity: Instant,
    autolock: Duration,
    vault_path: PathBuf,
}

impl Session {
    fn new() -> Self {
        Self {
            unlocked: None,
            last_activity: Instant::now(),
            autolock: DEFAULT_AUTOLOCK,
            vault_path: std::env::var_os("TREZOR_PROTECTOR_VAULT")
                .map(PathBuf::from)
                .unwrap_or_else(vault::default_path),
        }
    }

    fn lock(&mut self) {
        // Dropping the UnlockedVault zeroizes entries and the vault key.
        self.unlocked = None;
    }

    /// Enforce the idle timeout; returns the vault if still unlocked.
    fn vault(&mut self) -> Option<&mut UnlockedVault> {
        if self.unlocked.is_some() && self.last_activity.elapsed() > self.autolock {
            self.lock();
        }
        self.last_activity = Instant::now();
        self.unlocked.as_mut()
    }
}

fn host_loop() {
    let mut session = Session::new();
    while let Some(msg) = read_msg() {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let cmd = msg.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
        let reply = handle(&mut session, cmd, &msg, &id);
        let mut reply = match reply {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e.to_string(),
                              "locked": session.unlocked.is_none() }),
        };
        reply["id"] = id;
        write_msg(&reply);
    }
    // stdin EOF: browser gone — Session drop wipes the keys.
}

fn handle(session: &mut Session, cmd: &str, msg: &Value, id: &Value) -> Result<Value> {
    match cmd {
        "status" => {
            let unlocked = session.vault().is_some();
            Ok(json!({
                "ok": true,
                "unlocked": unlocked,
                "vault_exists": Vault::exists(&session.vault_path),
                "entry_count": session.unlocked.as_ref().map(|v| v.entries().len()),
                "autolock_minutes": session.autolock.as_secs() / 60,
            }))
        }

        "configure" => {
            if let Some(mins) = msg.get("autolock_minutes").and_then(|m| m.as_u64()) {
                session.autolock = Duration::from_secs(mins.clamp(1, 240) * 60);
            }
            Ok(json!({ "ok": true, "autolock_minutes": session.autolock.as_secs() / 60 }))
        }

        "unlock" => {
            if session.vault().is_some() {
                let count = session.unlocked.as_ref().map(|v| v.entries().len());
                return Ok(json!({ "ok": true, "entry_count": count }));
            }
            let locked = Vault::load(&session.vault_path)?;
            let wrapped = locked.wrapped_master_key()?;

            let mut trezor = connect_with_retry()?;
            // Prefer native GUI dialogs (tp-gui next to this binary); fall
            // back to relaying PIN/passphrase entry through the popup.
            let master = if gui_path().is_some() {
                let mut interaction = GuiInteraction { id: id.clone() };
                trezor.decrypt_master_key(&wrapped, &mut interaction)?
            } else {
                let mut interaction = BrowserInteraction { id: id.clone() };
                trezor.decrypt_master_key(&wrapped, &mut interaction)?
            };
            let unlocked = locked.unlock(&master)?;
            let count = unlocked.entries().len();
            session.unlocked = Some(unlocked);
            session.last_activity = Instant::now();
            Ok(json!({ "ok": true, "entry_count": count }))
        }

        "lock" => {
            session.lock();
            Ok(json!({ "ok": true }))
        }

        "list" => {
            let query = msg.get("query").and_then(|q| q.as_str()).unwrap_or("");
            let vault = session
                .vault()
                .ok_or_else(|| Error::Vault("locked".into()))?;
            let entries: Vec<Value> = vault
                .find(query)
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "name": e.name,
                        "username": e.username,
                        "url": e.url,
                        "has_totp": e.totp_secret.is_some(),
                    })
                })
                .collect();
            Ok(json!({ "ok": true, "entries": entries }))
        }

        "get" => {
            let entry_id = msg
                .get("entry_id")
                .and_then(|e| e.as_str())
                .ok_or_else(|| Error::InvalidInput("missing entry_id".into()))?;
            let vault = session
                .vault()
                .ok_or_else(|| Error::Vault("locked".into()))?;
            let entry = vault
                .get(entry_id)
                .ok_or_else(|| Error::NotFound("entry".into()))?;
            Ok(json!({
                "ok": true,
                "name": entry.name,
                "username": entry.username,
                "url": entry.url,
                "password": entry.password,
                "notes": entry.notes,
            }))
        }

        "totp" => {
            let entry_id = msg
                .get("entry_id")
                .and_then(|e| e.as_str())
                .ok_or_else(|| Error::InvalidInput("missing entry_id".into()))?;
            let vault = session
                .vault()
                .ok_or_else(|| Error::Vault("locked".into()))?;
            let entry = vault
                .get(entry_id)
                .ok_or_else(|| Error::NotFound("entry".into()))?;
            let secret = entry
                .totp_secret
                .as_deref()
                .ok_or_else(|| Error::NotFound("no TOTP secret on this entry".into()))?;
            let code = Totp::from_base32(secret)?.now()?;
            Ok(json!({ "ok": true, "code": code.code,
                       "seconds_remaining": code.seconds_remaining }))
        }

        // Save a password captured by the extension (explicit user click in
        // the popup; the content script itself can never write the vault).
        "add" => {
            let get = |k: &str| msg.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = get("name");
            let password = get("password");
            if name.is_empty() || password.is_empty() {
                return Err(Error::InvalidInput("add needs name and password".into()));
            }
            let vault = session
                .vault()
                .ok_or_else(|| Error::Vault("locked".into()))?;
            let entry = vault::Entry::new(&name, &get("username"), &get("url"), &password, "");
            let entry_id = vault.add(entry)?;
            Ok(json!({ "ok": true, "entry_id": entry_id }))
        }

        "update_password" => {
            let entry_id = msg
                .get("entry_id")
                .and_then(|e| e.as_str())
                .ok_or_else(|| Error::InvalidInput("missing entry_id".into()))?
                .to_string();
            let password = msg
                .get("password")
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| Error::InvalidInput("missing password".into()))?
                .to_string();
            let vault = session
                .vault()
                .ok_or_else(|| Error::Vault("locked".into()))?;
            let mut patch = vault::EntryPatch::empty();
            patch.password = Some(password);
            vault.update(&entry_id, patch)?;
            Ok(json!({ "ok": true }))
        }

        "generate" => {
            if msg.get("passphrase").and_then(|p| p.as_bool()).unwrap_or(false) {
                let words = msg.get("words").and_then(|w| w.as_u64()).unwrap_or(6) as usize;
                let value = passwords::generate_passphrase(words, "-")?;
                return Ok(json!({ "ok": true, "value": value.as_str(),
                                  "bits": words as f64 * 8.0 }));
            }
            let opts = GenerateOptions {
                length: msg.get("length").and_then(|l| l.as_u64()).unwrap_or(20) as usize,
                upper: msg.get("upper").and_then(|b| b.as_bool()).unwrap_or(true),
                digits: msg.get("digits").and_then(|b| b.as_bool()).unwrap_or(true),
                symbols: msg.get("symbols").and_then(|b| b.as_bool()).unwrap_or(true),
                avoid_ambiguous: msg
                    .get("avoid_ambiguous")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false),
            };
            let value = passwords::generate(&opts)?;
            let bits = passwords::entropy_bits(&value);
            Ok(json!({ "ok": true, "value": value.as_str(), "bits": bits }))
        }

        other => Err(Error::InvalidInput(format!("unknown command '{other}'"))),
    }
}

// ---------------------------------------------------------------------------
// Device interaction relayed through the extension popup
// ---------------------------------------------------------------------------

struct BrowserInteraction {
    id: Value,
}

impl BrowserInteraction {
    /// Emit an event and wait for the matching answer from the extension.
    /// Unrelated commands arriving meanwhile get a "busy" reply.
    fn ask(&self, event: &str, expect_cmd: &str) -> Result<Zeroizing<String>> {
        write_msg(&json!({ "id": self.id, "event": event }));
        loop {
            let msg = read_msg()
                .ok_or_else(|| Error::Trezor("browser disconnected during unlock".into()))?;
            let cmd = msg.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
            if cmd == expect_cmd {
                let value = msg.get("value").and_then(|v| v.as_str()).unwrap_or("");
                return Ok(Zeroizing::new(value.to_string()));
            }
            if cmd == "cancel" {
                return Err(Error::Trezor("unlock cancelled".into()));
            }
            let busy_id = msg.get("id").cloned().unwrap_or(Value::Null);
            write_msg(&json!({ "id": busy_id, "ok": false,
                               "error": "busy: device interaction in progress" }));
        }
    }
}

impl Interaction for BrowserInteraction {
    fn pin(&mut self) -> Result<String> {
        Ok(self.ask("pin_request", "pin")?.to_string())
    }

    fn passphrase(&mut self) -> Result<Option<String>> {
        let value = self.ask("passphrase_request", "passphrase")?;
        if value.is_empty() {
            Ok(None) // enter on device
        } else {
            Ok(Some(value.to_string()))
        }
    }

    fn notify_button(&mut self) {
        write_msg(&json!({ "id": self.id, "event": "button" }));
    }
}

// ---------------------------------------------------------------------------
// Device interaction via native GUI dialogs (tp-gui)
// ---------------------------------------------------------------------------

/// Locate tp-gui next to this executable, if installed.
fn gui_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = if cfg!(windows) { "tp-gui.exe" } else { "tp-gui" };
    let candidate = dir.join(name);
    candidate.exists().then_some(candidate)
}

/// Run a tp-gui dialog mode. Returns Ok(Some(line)) on confirm,
/// Ok(None) on user cancel.
fn run_gui_dialog(mode: &str) -> Result<Option<String>> {
    let gui = gui_path().ok_or_else(|| Error::Trezor("tp-gui not found".into()))?;
    let output = std::process::Command::new(gui)
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Trezor(format!("cannot launch tp-gui: {e}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&output.stdout).trim_end().to_string();
    Ok(Some(line))
}

/// Connect to the device; if none is present and tp-gui is available, show
/// a "connect your Trezor" prompt with retry.
fn connect_with_retry() -> Result<TrezorManager> {
    let mut last_err = None;
    for _ in 0..5 {
        match TrezorManager::connect() {
            Ok(manager) => return Ok(manager),
            Err(e) => {
                last_err = Some(e);
                if gui_path().is_none() || run_gui_dialog("connect")?.is_none() {
                    break; // no GUI or user cancelled
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Trezor("no Trezor device found".into())))
}

struct GuiInteraction {
    id: Value,
}

impl Interaction for GuiInteraction {
    fn pin(&mut self) -> Result<String> {
        run_gui_dialog("pin")?
            .ok_or_else(|| Error::Trezor("PIN entry cancelled".into()))
    }

    fn passphrase(&mut self) -> Result<Option<String>> {
        match run_gui_dialog("passphrase")? {
            None => Err(Error::Trezor("passphrase entry cancelled".into())),
            Some(value) if value.is_empty() => Ok(None), // enter on device
            Some(value) => Ok(Some(value)),
        }
    }

    fn notify_button(&mut self) {
        // Keep the popup informed; the device itself shows what to confirm.
        write_msg(&json!({ "id": self.id, "event": "button" }));
    }
}

// ---------------------------------------------------------------------------
// install / uninstall
// ---------------------------------------------------------------------------

fn install(args: &[String]) -> Result<String> {
    let mut extension_id = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--extension-id" {
            extension_id = iter.next().cloned();
        }
    }
    let extension_id = extension_id.ok_or_else(|| {
        Error::InvalidInput(
            "usage: tp-host install --extension-id <id>\n\
             (find the id at chrome://extensions after loading the extension)"
                .into(),
        )
    })?;
    if !extension_id.chars().all(|c| c.is_ascii_lowercase()) || extension_id.len() != 32 {
        return Err(Error::InvalidInput(
            "extension id must be 32 lowercase letters".into(),
        ));
    }

    let exe = std::env::current_exe()?;
    let manifest = json!({
        "name": HOST_NAME,
        "description": "TrezorProtector native messaging host",
        "path": exe.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    });

    let dir = manifest_dir()?;
    std::fs::create_dir_all(&dir)?;
    let manifest_path = dir.join(format!("{HOST_NAME}.json"));
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    register(&manifest_path)?;
    Ok(format!(
        "Registered native messaging host for extension {extension_id}.\n\
         Manifest: {}",
        manifest_path.display()
    ))
}

fn manifest_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| Error::InvalidInput("LOCALAPPDATA not set".into()))?;
        Ok(PathBuf::from(base).join("TrezorProtector"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| Error::InvalidInput("HOME not set".into()))?;
        Ok(PathBuf::from(home).join(".trezorprotector"))
    }
}

#[cfg(windows)]
fn register(manifest_path: &std::path::Path) -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for browser_key in [
        format!("Software\\Google\\Chrome\\NativeMessagingHosts\\{HOST_NAME}"),
        format!("Software\\Microsoft\\Edge\\NativeMessagingHosts\\{HOST_NAME}"),
    ] {
        let (key, _) = hkcu
            .create_subkey(&browser_key)
            .map_err(|e| Error::InvalidInput(format!("registry write failed: {e}")))?;
        key.set_value("", &manifest_path.to_string_lossy().to_string())
            .map_err(|e| Error::InvalidInput(format!("registry write failed: {e}")))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn register(manifest_path: &std::path::Path) -> Result<()> {
    // Chrome on Linux/macOS reads manifests from fixed per-user directories.
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::InvalidInput("HOME not set".into()))?;
    let home = PathBuf::from(home);
    let targets = [
        // Linux
        home.join(".config/google-chrome/NativeMessagingHosts"),
        home.join(".config/chromium/NativeMessagingHosts"),
        home.join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        home.join(".config/microsoft-edge/NativeMessagingHosts"),
        // macOS
        home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"),
        home.join("Library/Application Support/Chromium/NativeMessagingHosts"),
    ];
    for dir in targets {
        if dir.parent().map(|p| p.exists()).unwrap_or(false) {
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(manifest_path, dir.join(format!("{HOST_NAME}.json")))?;
        }
    }
    Ok(())
}

fn uninstall() -> Result<()> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for browser_key in [
            format!("Software\\Google\\Chrome\\NativeMessagingHosts\\{HOST_NAME}"),
            format!("Software\\Microsoft\\Edge\\NativeMessagingHosts\\{HOST_NAME}"),
        ] {
            let _ = hkcu.delete_subkey_all(&browser_key);
        }
    }
    let dir = manifest_dir()?;
    let _ = std::fs::remove_file(dir.join(format!("{HOST_NAME}.json")));
    Ok(())
}
