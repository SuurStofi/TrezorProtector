//! Terminal-side device interaction and unlock helpers.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use colored::Colorize;
use tp_core::crypto::SecretKey;
use tp_core::trezor::{Interaction, TrezorManager};
use tp_core::vault::{self, UnlockedVault, Vault};
use tp_core::{Error, Result};

pub struct TermInteraction;

impl Interaction for TermInteraction {
    fn pin(&mut self) -> Result<String> {
        println!();
        println!("  {}", "A scrambled PIN keypad is shown on your Trezor.".yellow());
        println!("  Enter the {} of your PIN digits using this layout:", "POSITIONS".bold());
        println!();
        println!("      {}", "7 8 9".cyan().bold());
        println!("      {}", "4 5 6".cyan().bold());
        println!("      {}", "1 2 3".cyan().bold());
        println!();
        let pin = rpassword::prompt_password("  PIN positions: ")
            .map_err(|e| Error::InvalidInput(format!("cannot read PIN: {e}")))?;
        Ok(pin.trim().to_string())
    }

    fn passphrase(&mut self) -> Result<Option<String>> {
        println!();
        println!("  Passphrase requested. Press Enter to type it ON THE DEVICE (recommended),");
        let phrase = rpassword::prompt_password("  or type it here (hidden): ")
            .map_err(|e| Error::InvalidInput(format!("cannot read passphrase: {e}")))?;
        if phrase.is_empty() {
            Ok(None)
        } else {
            Ok(Some(phrase))
        }
    }

    fn notify_button(&mut self) {
        println!("  {}", ">> Confirm the action on your Trezor…".yellow().bold());
    }
}

pub fn resolve_vault_path(cli_path: &Option<PathBuf>) -> PathBuf {
    if let Some(p) = cli_path {
        return p.clone();
    }
    if let Some(env) = std::env::var_os("TREZOR_PROTECTOR_VAULT") {
        return PathBuf::from(env);
    }
    vault::default_path()
}

pub fn connect() -> Result<TrezorManager> {
    println!("{}", "Connecting to Trezor…".yellow());
    let manager = TrezorManager::connect()?;
    let info = manager.info()?;
    println!(
        "{} {} '{}' {}",
        "Connected:".green().bold(),
        info.model.bold(),
        info.label,
        format!("(firmware {})", info.firmware).dimmed()
    );
    Ok(manager)
}

/// Load the vault, connect to the device, and unwrap the master key.
pub fn unlock(path: &Path) -> Result<(SecretKey, UnlockedVault)> {
    let locked = Vault::load(path)?;
    let wrapped = locked.wrapped_master_key()?;

    let mut trezor = connect()?;
    println!("{}", "Unlocking vault — confirm on your Trezor…".yellow());
    let master = trezor.decrypt_master_key(&wrapped, &mut TermInteraction)?;

    let unlocked = locked.unlock(&master)?;
    println!(
        "{} {}\n",
        "Vault unlocked.".green().bold(),
        format!("({} entries)", unlocked.entries().len()).dimmed()
    );
    Ok((master, unlocked))
}

/// Ask a yes/no question on the terminal.
pub fn confirm(question: &str) -> bool {
    print!("{question} [y/N] ");
    io::stdout().flush().ok();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Read one line from stdin.
pub fn prompt(question: &str) -> Result<String> {
    print!("{question}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::InvalidInput(format!("cannot read input: {e}")))?;
    Ok(line.trim().to_string())
}

/// Prompt twice for a hidden password and make sure both match.
pub fn prompt_new_password(label: &str) -> Result<String> {
    let first = rpassword::prompt_password(format!("{label}: "))
        .map_err(|e| Error::InvalidInput(format!("cannot read password: {e}")))?;
    let second = rpassword::prompt_password("Repeat to confirm: ")
        .map_err(|e| Error::InvalidInput(format!("cannot read password: {e}")))?;
    if first != second {
        return Err(Error::InvalidInput("passwords do not match".into()));
    }
    Ok(first)
}

/// Pick one entry among the matches for a query (interactive when ambiguous).
pub fn pick_entry<'a>(
    vault: &'a UnlockedVault,
    query: &str,
) -> Result<&'a tp_core::vault::Entry> {
    let matches = vault.find(query);
    match matches.len() {
        0 => Err(Error::NotFound(format!("no entries matching '{query}'"))),
        1 => Ok(matches[0]),
        _ => {
            println!("Multiple matches:");
            for (i, e) in matches.iter().enumerate() {
                println!("  {}. {}  ({})", i + 1, e.name, e.username);
            }
            let choice = prompt("Select number: ")?;
            let idx: usize = choice
                .parse()
                .map_err(|_| Error::InvalidInput("not a number".into()))?;
            matches
                .get(idx.saturating_sub(1))
                .copied()
                .ok_or_else(|| Error::InvalidInput("selection out of range".into()))
        }
    }
}

/// Copy to clipboard and clear it after `secs` seconds (blocking countdown).
pub fn copy_with_autoclear(text: &str, secs: u64, what: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| Error::InvalidInput(format!("clipboard unavailable: {e}")))?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| Error::InvalidInput(format!("clipboard write failed: {e}")))?;
    println!("{what} copied to clipboard.");

    if secs == 0 {
        println!("Auto-clear disabled (--clear-after 0). Clear it yourself when done!");
        return Ok(());
    }
    print!("Clearing clipboard in {secs}s (Ctrl+C keeps it)… ");
    io::stdout().flush().ok();
    std::thread::sleep(std::time::Duration::from_secs(secs));
    // Only clear if the clipboard still holds our secret.
    if clipboard.get_text().map(|t| t == text).unwrap_or(false) {
        clipboard.set_text(String::new()).ok();
        println!("cleared.");
    } else {
        println!("clipboard changed meanwhile — left as is.");
    }
    Ok(())
}
