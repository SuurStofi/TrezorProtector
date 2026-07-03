//! TrezorProtector CLI (`tp`) — hardware-backed password manager and file
//! encryption.

#![forbid(unsafe_code)]

mod interact;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use colored::Colorize;
use zeroize::Zeroizing;

use tp_core::crypto::SecretKey;
use tp_core::passwords::{self, GenerateOptions};
use tp_core::totp::Totp;
use tp_core::vault::{self, Entry, EntryPatch, Vault};
use tp_core::{audit, files, Error, Result};

use interact::TermInteraction;

#[derive(Parser)]
#[command(
    name = "tp",
    version,
    about = "TrezorProtector — password manager & file encryption backed by your Trezor"
)]
struct Cli {
    /// Vault file path (env: TREZOR_PROTECTOR_VAULT)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault bound to your Trezor device
    Init,
    /// Show device and vault status
    Status,
    /// Upgrade a legacy Python (v1) vault to the v2 format
    Migrate {
        /// Path of the v1 vault (defaults to the --vault path)
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Password manager
    #[command(subcommand)]
    Pw(PwCommand),
    /// Show a time-based 2FA code for an entry
    Totp {
        query: String,
        /// Copy the code instead of printing it
        #[arg(long)]
        copy: bool,
    },
    /// Audit the vault for weak, reused, stale or breached passwords
    Audit {
        /// Days after which an unchanged password counts as stale
        #[arg(long, default_value_t = 365)]
        days: i64,
        /// Also check passwords against Have-I-Been-Pwned (k-anonymity;
        /// only 5 hex chars of a hash ever leave this machine)
        #[arg(long)]
        hibp: bool,
    },
    /// File encryption
    #[command(subcommand)]
    File(FileCommand),
    /// Vault maintenance: backup, restore, key rotation
    #[command(subcommand)]
    Vault(VaultCommand),
}

#[derive(Subcommand)]
enum PwCommand {
    /// Add a new entry
    Add {
        name: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long, default_value = "")]
        url: String,
        /// Password value (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long, default_value = "")]
        notes: String,
        /// Generate a strong random password instead of typing one
        #[arg(short, long)]
        generate: bool,
        /// TOTP secret (base32 or otpauth:// URI) to store with the entry
        #[arg(long)]
        totp: Option<String>,
        /// Comma-separated tags
        #[arg(long)]
        tags: Option<String>,
    },
    /// List entries (metadata only, passwords stay hidden)
    List {
        #[arg(short, long, default_value = "")]
        search: String,
    },
    /// Show one entry
    Get {
        query: String,
        /// Print the password in clear text
        #[arg(long)]
        show: bool,
    },
    /// Copy a password to the clipboard (auto-clears)
    Copy {
        query: String,
        /// Seconds before the clipboard is wiped (0 = never)
        #[arg(long, default_value_t = 30)]
        clear_after: u64,
        /// Copy the username instead of the password
        #[arg(long)]
        username: bool,
    },
    /// Edit an existing entry
    Update {
        query: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(short, long)]
        notes: Option<String>,
        /// Prompt for a new password
        #[arg(long)]
        new_password: bool,
        /// Generate a new password
        #[arg(short, long)]
        generate: bool,
        /// Set/replace the TOTP secret (base32 or otpauth:// URI)
        #[arg(long)]
        totp: Option<String>,
        /// Remove the stored TOTP secret
        #[arg(long)]
        clear_totp: bool,
        /// Comma-separated tags (replaces existing tags)
        #[arg(long)]
        tags: Option<String>,
    },
    /// Delete an entry
    Delete {
        query: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Show previous passwords of an entry
    History { query: String },
    /// Generate passwords or passphrases (no Trezor required)
    Generate {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_upper: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        /// Skip look-alike characters (0/O, 1/l/I …)
        #[arg(long)]
        avoid_ambiguous: bool,
        #[arg(short, long, default_value_t = 5)]
        count: usize,
        /// Generate word-based passphrases instead
        #[arg(long)]
        passphrase: bool,
        /// Words per passphrase
        #[arg(long, default_value_t = 6)]
        words: usize,
    },
}

#[derive(Subcommand)]
enum FileCommand {
    /// Encrypt a file (streaming, any size)
    Encrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Securely overwrite and delete the original afterwards
        #[arg(long)]
        shred_original: bool,
    },
    /// Decrypt a .tpenc file (v2 and legacy v1)
    Decrypt {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a text file and print it — nothing touches the disk
    View { input: PathBuf },
    /// Securely overwrite and delete a plaintext file
    Shred {
        input: PathBuf,
        #[arg(long, default_value_t = 3)]
        passes: u32,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Export all entries into a password-protected backup
    /// (Argon2id + AES-256-GCM — recoverable WITHOUT the Trezor)
    Export { output: PathBuf },
    /// Import entries from a backup file (merge by id, newest wins)
    Import { input: PathBuf },
    /// Re-wrap the vault under a fresh master key
    RotateKey,
}

fn main() -> ExitCode {
    // Enable ANSI colors on legacy Windows consoles (no-op elsewhere).
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).ok();

    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let vault_path = interact::resolve_vault_path(&cli.vault);
    match cli.command {
        Command::Init => cmd_init(&vault_path),
        Command::Status => cmd_status(&vault_path),
        Command::Migrate { from } => cmd_migrate(&vault_path, from),
        Command::Pw(cmd) => cmd_pw(&vault_path, cmd),
        Command::Totp { query, copy } => cmd_totp(&vault_path, &query, copy),
        Command::Audit { days, hibp } => cmd_audit(&vault_path, days, hibp),
        Command::File(cmd) => cmd_file(&vault_path, cmd),
        Command::Vault(cmd) => cmd_vault(&vault_path, cmd),
    }
}

// ---------------------------------------------------------------------------
// init / status / migrate
// ---------------------------------------------------------------------------

fn cmd_init(path: &PathBuf) -> Result<()> {
    if Vault::exists(path)
        && !interact::confirm(&format!(
            "A vault already exists at {}. Overwrite it (the old file is kept as .bak)?",
            path.display()
        ))
    {
        println!("Aborted.");
        return Ok(());
    }

    let mut trezor = interact::connect()?;
    let master = SecretKey::generate();
    println!("Wrapping master key — confirm on your Trezor…");
    let wrapped = trezor.encrypt_master_key(&master, &mut TermInteraction)?;
    Vault::create(path, &wrapped, &master)?;

    println!();
    println!(
        "{} {}",
        "Vault created at".green().bold(),
        path.display().to_string().bold()
    );
    println!("The master key is wrapped by your Trezor: only that physical device");
    println!("(with the same seed & passphrase) can ever unlock this vault.");
    println!();
    println!("Tip: run `tp vault export backup.tpbackup` to create a password-");
    println!("protected recovery file in case the device is ever lost.");
    Ok(())
}

fn cmd_status(path: &PathBuf) -> Result<()> {
    println!("Vault path : {}", path.display());
    if Vault::exists(path) {
        match Vault::load(path) {
            Ok(_) => println!("Vault      : found (v2, contents encrypted)"),
            Err(e) => println!("Vault      : {e}"),
        }
    } else {
        println!("Vault      : not found — run `tp init`");
    }

    match tp_core::trezor::TrezorManager::connect() {
        Ok(manager) => {
            let info = manager.info()?;
            println!("Trezor     : {} '{}'", info.model, info.label);
            println!("Firmware   : {}", info.firmware);
            println!("Initialized: {}", if info.initialized { "yes" } else { "no" });
        }
        Err(e) => println!("Trezor     : not connected ({e})"),
    }
    Ok(())
}

fn cmd_migrate(vault_path: &PathBuf, from: Option<PathBuf>) -> Result<()> {
    let src = from.unwrap_or_else(|| vault_path.clone());
    println!("Migrating v1 vault {} → v2…", src.display());

    let wrapped = vault::read_v1_wrapped_key(&src)?;
    let mut trezor = interact::connect()?;
    println!("Unlocking with your Trezor — confirm on the device…");
    let master = trezor.decrypt_master_key(&wrapped, &mut TermInteraction)?;

    let entries = vault::read_v1_entries(&src, &master)?;
    println!("Decrypted {} entries from the v1 vault.", entries.len());

    // Keep a copy of the original before writing anything.
    let backup = src.with_extension("v1.bak");
    std::fs::copy(&src, &backup)?;
    println!("Original saved as {}", backup.display());

    vault::create_from_entries(vault_path, &wrapped, &master, entries)?;
    println!("Done. v2 vault written to {}", vault_path.display());
    println!("v2 encrypts ALL metadata (names, usernames, URLs) — not just passwords.");
    Ok(())
}

// ---------------------------------------------------------------------------
// pw
// ---------------------------------------------------------------------------

fn parse_totp_secret(input: &str) -> Result<String> {
    // Accept both bare base32 and otpauth:// URIs; store normalized base32.
    if input.starts_with("otpauth://") {
        Totp::from_otpauth(input)?;
        let secret = input
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("secret="))
            .ok_or_else(|| Error::InvalidInput("otpauth URI missing secret".into()))?;
        Ok(secret.to_string())
    } else {
        Totp::from_base32(input)?;
        Ok(input.split_whitespace().collect::<String>().to_uppercase())
    }
}

fn parse_tags(tags: &str) -> Vec<String> {
    tags.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn cmd_pw(vault_path: &PathBuf, cmd: PwCommand) -> Result<()> {
    match cmd {
        PwCommand::Generate {
            length,
            no_upper,
            no_digits,
            no_symbols,
            avoid_ambiguous,
            count,
            passphrase,
            words,
        } => {
            // No vault or device needed.
            for i in 1..=count.clamp(1, 100) {
                let (value, bits): (Zeroizing<String>, f64) = if passphrase {
                    // 256-word list → exactly 8 bits of entropy per word.
                    (passwords::generate_passphrase(words, "-")?, words as f64 * 8.0)
                } else {
                    let pw = passwords::generate(&GenerateOptions {
                        length,
                        upper: !no_upper,
                        digits: !no_digits,
                        symbols: !no_symbols,
                        avoid_ambiguous,
                    })?;
                    let bits = passwords::entropy_bits(&pw);
                    (pw, bits)
                };
                println!(
                    "  {} {}   {}",
                    format!("{i}.").dimmed(),
                    value.as_str().bold(),
                    colored_strength(bits)
                );
            }
            return Ok(());
        }
        _ => {}
    }

    let (_master, mut unlocked) = interact::unlock(vault_path)?;

    match cmd {
        PwCommand::Add { name, username, url, password, notes, generate, totp, tags } => {
            let username = match username {
                Some(u) => u,
                None => interact::prompt("Username / e-mail: ")?,
            };
            let password: Zeroizing<String> = if generate {
                let pw = passwords::generate(&GenerateOptions::default())?;
                println!("Generated password: {}", pw.as_str());
                pw
            } else if let Some(p) = password {
                Zeroizing::new(p)
            } else {
                Zeroizing::new(interact::prompt_new_password("Password")?)
            };

            let mut entry = Entry::new(&name, &username, &url, &password, &notes);
            if let Some(t) = totp {
                entry.totp_secret = Some(parse_totp_secret(&t)?);
            }
            if let Some(t) = tags {
                entry.tags = parse_tags(&t);
            }
            let id = unlocked.add(entry)?;
            println!(
                "{} '{}' {}",
                "Saved".green().bold(),
                name.cyan(),
                format!("(id {}…)", &id[..8]).dimmed()
            );
        }

        PwCommand::List { search } => {
            let entries = unlocked.find(&search);
            if entries.is_empty() {
                println!("No entries found.");
                return Ok(());
            }
            println!(
                "{}",
                format!(
                    "{:<10} {:<28} {:<26} {:<30} {}",
                    "ID", "NAME", "USERNAME", "URL", "2FA"
                )
                .bold()
                .underline()
            );
            for e in entries {
                println!(
                    "{:<10} {:<28} {:<26} {:<30} {}",
                    e.id[..8].dimmed(),
                    truncate(&e.name, 26).cyan(),
                    truncate(&e.username, 24),
                    truncate(&e.url, 28).blue(),
                    if e.totp_secret.is_some() { "yes".green().to_string() } else { String::new() }
                );
            }
        }

        PwCommand::Get { query, show } => {
            let entry = interact::pick_entry(&unlocked, &query)?;
            let label = |t: &str| format!("{t:<9}:").cyan().bold().to_string();
            println!();
            println!("{} {}", label("Name"), entry.name.bold());
            println!("{} {}", label("Username"), entry.username);
            if !entry.url.is_empty() {
                println!("{} {}", label("URL"), entry.url.blue());
            }
            if show {
                println!("{} {}", label("Password"), entry.password);
            } else {
                println!(
                    "{} {}  {}",
                    label("Password"),
                    "•".repeat(entry.password.chars().count().min(20)).dimmed(),
                    "(use --show to reveal)".dimmed()
                );
            }
            if !entry.notes.is_empty() {
                println!("{} {}", label("Notes"), entry.notes);
            }
            if !entry.tags.is_empty() {
                println!("{} {}", label("Tags"), entry.tags.join(", "));
            }
            if entry.totp_secret.is_some() {
                println!(
                    "{} {}",
                    label("2FA"),
                    format!("stored (run `tp totp {}`)", entry.name).green()
                );
            }
            println!("{} {}", label("Updated"), entry.updated_at.dimmed());
        }

        PwCommand::Copy { query, clear_after, username } => {
            let entry = interact::pick_entry(&unlocked, &query)?;
            if username {
                interact::copy_with_autoclear(&entry.username, 0, "Username")?;
            } else {
                let secret = Zeroizing::new(entry.password.clone());
                interact::copy_with_autoclear(
                    &secret,
                    clear_after,
                    &format!("Password for '{}'", entry.name),
                )?;
            }
        }

        PwCommand::Update {
            query,
            name,
            username,
            url,
            notes,
            new_password,
            generate,
            totp,
            clear_totp,
            tags,
        } => {
            let (entry_id, entry_name) = {
                let e = interact::pick_entry(&unlocked, &query)?;
                (e.id.clone(), e.name.clone())
            };

            let mut patch = EntryPatch::empty();
            patch.name = name;
            patch.username = username;
            patch.url = url;
            patch.notes = notes;
            if generate {
                let pw = passwords::generate(&GenerateOptions::default())?;
                println!("New password: {}", pw.as_str());
                patch.password = Some(pw.to_string());
            } else if new_password {
                patch.password = Some(interact::prompt_new_password("New password")?);
            }
            if clear_totp {
                patch.totp_secret = Some(None);
            } else if let Some(t) = totp {
                patch.totp_secret = Some(Some(parse_totp_secret(&t)?));
            }
            if let Some(t) = tags {
                patch.tags = Some(parse_tags(&t));
            }
            unlocked.update(&entry_id, patch)?;
            println!("Updated '{entry_name}'.");
        }

        PwCommand::Delete { query, yes } => {
            let entry = interact::pick_entry(&unlocked, &query)?;
            let (id, name) = (entry.id.clone(), entry.name.clone());
            if yes || interact::confirm(&format!("Delete '{name}'?")) {
                unlocked.delete(&id)?;
                println!("Deleted '{name}'.");
            } else {
                println!("Cancelled.");
            }
        }

        PwCommand::History { query } => {
            let entry = interact::pick_entry(&unlocked, &query)?;
            if entry.history.is_empty() {
                println!("No password history for '{}'.", entry.name);
            } else {
                println!("Previous passwords for '{}':", entry.name);
                for h in &entry.history {
                    println!("  replaced {}: {}", h.replaced_at, h.password);
                }
            }
        }

        PwCommand::Generate { .. } => unreachable!("handled above"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// totp
// ---------------------------------------------------------------------------

fn cmd_totp(vault_path: &PathBuf, query: &str, copy: bool) -> Result<()> {
    let (_master, unlocked) = interact::unlock(vault_path)?;
    let entry = interact::pick_entry(&unlocked, query)?;
    let secret = entry.totp_secret.as_deref().ok_or_else(|| {
        Error::NotFound(format!(
            "'{}' has no TOTP secret — add one with `tp pw update {} --totp <secret>`",
            entry.name, entry.name
        ))
    })?;
    let code = Totp::from_base32(secret)?.now()?;
    if copy {
        interact::copy_with_autoclear(&code.code, 30, "TOTP code")?;
    } else {
        println!(
            "{}  (valid for {}s)",
            code.code, code.seconds_remaining
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

fn cmd_audit(vault_path: &PathBuf, days: i64, hibp: bool) -> Result<()> {
    let (_master, unlocked) = interact::unlock(vault_path)?;
    let entries = unlocked.entries();

    let findings = audit::audit(entries, days);
    let mut issues = 0;
    for f in &findings {
        let label = match f.kind {
            audit::FindingKind::WeakPassword => "WEAK    ".red().bold().to_string(),
            audit::FindingKind::ReusedPassword => "REUSED  ".yellow().bold().to_string(),
            audit::FindingKind::StalePassword => "STALE   ".yellow().to_string(),
            audit::FindingKind::MissingTotp => "NO-2FA  ".dimmed().to_string(),
        };
        // 2FA nudges are informational, not issues.
        if f.kind != audit::FindingKind::MissingTotp {
            issues += 1;
        }
        println!("{label} {:<28} {}", truncate(&f.entry_name, 26), f.detail);
    }

    if hibp {
        println!();
        println!("Checking Have-I-Been-Pwned (k-anonymity: only 5 hash chars are sent)…");
        for e in entries {
            let (prefix, suffix) = audit::hibp_parts(&e.password);
            match hibp_range(&prefix) {
                Ok(body) => {
                    let hit = body.lines().find_map(|line| {
                        let (s, count) = line.trim().split_once(':')?;
                        (s.eq_ignore_ascii_case(&suffix)).then(|| count.trim().to_string())
                    });
                    if let Some(count) = hit {
                        issues += 1;
                        println!(
                            "{} {:<28} seen {count} times in public breaches — change it!",
                            "BREACHED".red().bold(),
                            truncate(&e.name, 26)
                        );
                    }
                }
                Err(e) => {
                    println!("  (HIBP check failed: {e})");
                    break;
                }
            }
        }
    }

    println!();
    if issues == 0 {
        println!(
            "{}",
            format!("No problems found across {} entries. Nice.", entries.len())
                .green()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!("{issues} issue(s) across {} entries.", entries.len())
                .yellow()
                .bold()
        );
    }
    Ok(())
}

fn hibp_range(prefix: &str) -> Result<String> {
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let resp = ureq::get(&url)
        .set("Add-Padding", "true")
        .set("User-Agent", "TrezorProtector-audit")
        .call()
        .map_err(|e| Error::InvalidInput(format!("HIBP request failed: {e}")))?;
    resp.into_string()
        .map_err(|e| Error::InvalidInput(format!("HIBP response unreadable: {e}")))
}

// ---------------------------------------------------------------------------
// file
// ---------------------------------------------------------------------------

fn cmd_file(vault_path: &PathBuf, cmd: FileCommand) -> Result<()> {
    // Shred never needs the vault or the device.
    if let FileCommand::Shred { input, passes, yes } = &cmd {
        if !yes && !interact::confirm(&format!(
            "Permanently destroy '{}'? This cannot be undone.",
            input.display()
        )) {
            println!("Cancelled.");
            return Ok(());
        }
        files::shred(input, *passes)?;
        println!("Shredded {} ({} random passes + zero pass).", input.display(), passes);
        println!("Note: on SSDs, full-disk encryption is the only hard guarantee.");
        return Ok(());
    }

    let (master, _unlocked) = interact::unlock(vault_path)?;
    match cmd {
        FileCommand::Encrypt { input, output, shred_original } => {
            let out = files::encrypt_file(&master, &input, output.as_deref())?;
            println!("Encrypted: {} -> {}", input.display(), out.display());
            if shred_original {
                files::shred(&input, 3)?;
                println!("Original shredded.");
            }
        }
        FileCommand::Decrypt { input, output } => {
            let (out, original) = files::decrypt_file(&master, &input, output.as_deref())?;
            println!(
                "Decrypted: {} -> {} (original name: {original})",
                input.display(),
                out.display()
            );
        }
        FileCommand::View { input } => {
            let (bytes, name) = files::read_encrypted(&master, &input)?;
            match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    println!("----- {name} (decrypted, not written to disk) -----");
                    println!("{text}");
                    println!("----- end -----");
                }
                Err(_) => {
                    println!("Binary file: {name} ({} bytes)", bytes.len());
                    println!("Use `tp file decrypt` to write it to disk.");
                }
            }
        }
        FileCommand::Shred { .. } => unreachable!("handled above"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

fn cmd_vault(vault_path: &PathBuf, cmd: VaultCommand) -> Result<()> {
    match cmd {
        VaultCommand::Export { output } => {
            let (_master, unlocked) = interact::unlock(vault_path)?;
            println!("This backup can be opened WITHOUT the Trezor — protect it with a");
            println!("strong password you will remember (a diceware passphrase is ideal).");
            let password = interact::prompt_new_password("Backup password (min 8 chars)")?;
            unlocked.export_backup(&output, &password)?;
            println!("Backup written to {}", output.display());
        }
        VaultCommand::Import { input } => {
            let (_master, mut unlocked) = interact::unlock(vault_path)?;
            let password = Zeroizing::new(
                rpassword::prompt_password("Backup password: ")
                    .map_err(|e| Error::InvalidInput(format!("cannot read password: {e}")))?,
            );
            let (added, updated) = unlocked.import_backup(&input, &password)?;
            println!("Imported: {added} new entries, {updated} updated.");
        }
        VaultCommand::RotateKey => {
            let (_old_master, mut unlocked) = interact::unlock(vault_path)?;
            println!("Generating a fresh master key and re-wrapping on the device…");
            let mut trezor = interact::connect()?;
            let new_master = SecretKey::generate();
            let new_wrapped = trezor.encrypt_master_key(&new_master, &mut TermInteraction)?;
            unlocked.rotate_key(&new_master, &new_wrapped)?;
            println!("Master key rotated. Old encrypted backups of the VAULT FILE are now");
            println!("undecryptable with the new key — but `tp vault export` backups still work.");
            println!("Note: files encrypted with `tp file encrypt` used the OLD key; decrypt");
            println!("them before rotating, or keep the old vault .bak file safe.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn colored_strength(bits: f64) -> String {
    let text = format!("[{:.0} bits, {}]", bits, passwords::strength_label(bits));
    if bits < 60.0 {
        text.red().to_string()
    } else if bits < 80.0 {
        text.yellow().to_string()
    } else {
        text.green().to_string()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
