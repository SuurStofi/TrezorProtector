//! Background worker that owns the Trezor connection and the unlocked
//! vault. The UI thread never blocks on USB traffic: it sends [`Cmd`]s and
//! renders [`Event`]s; device PIN/passphrase requests come back as events
//! and the answers return through the reply channel.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use tp_core::crypto::SecretKey;
use tp_core::trezor::{Interaction, TrezorManager};
use tp_core::vault::{self, Entry, EntryPatch, Vault};
use tp_core::{files, Error, Result};

pub enum Cmd {
    Unlock,
    Lock,
    Add {
        name: String,
        username: String,
        url: String,
        password: String,
        notes: String,
        totp: Option<String>,
    },
    Update {
        id: String,
        name: String,
        username: String,
        url: String,
        password: Option<String>,
        notes: String,
        totp: Option<Option<String>>,
    },
    Delete {
        id: String,
    },
    EncryptFile(PathBuf),
    DecryptFile(PathBuf),
}

pub enum Event {
    NeedPin,
    NeedPassphrase,
    ButtonWait,
    Unlocked(Vec<Entry>),
    Entries(Vec<Entry>),
    Locked,
    Error(String),
    Info(String),
}

pub enum Reply {
    Pin(String),
    Passphrase(Option<String>),
    Cancel,
}

pub struct WorkerHandle {
    pub cmd_tx: Sender<Cmd>,
    pub reply_tx: Sender<Reply>,
    pub event_rx: Receiver<Event>,
}

pub fn spawn(ctx: eframe::egui::Context) -> WorkerHandle {
    let (cmd_tx, cmd_rx) = channel::<Cmd>();
    let (reply_tx, reply_rx) = channel::<Reply>();
    let (event_tx, event_rx) = channel::<Event>();

    std::thread::spawn(move || {
        let mut session: Option<(SecretKey, vault::UnlockedVault)> = None;
        let vault_path = std::env::var_os("TREZOR_PROTECTOR_VAULT")
            .map(PathBuf::from)
            .unwrap_or_else(vault::default_path);

        let emit = |e: Event| {
            let _ = event_tx.send(e);
            ctx.request_repaint();
        };

        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                Cmd::Unlock => {
                    if session.is_some() {
                        continue;
                    }
                    match do_unlock(&vault_path, &event_tx, &reply_rx, &ctx) {
                        Ok((master, unlocked)) => {
                            emit(Event::Unlocked(unlocked.entries().to_vec()));
                            session = Some((master, unlocked));
                        }
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
                Cmd::Lock => {
                    session = None; // zeroizes keys + entries on drop
                    emit(Event::Locked);
                }
                Cmd::Add { name, username, url, password, notes, totp } => {
                    let Some((_, unlocked)) = session.as_mut() else {
                        emit(Event::Error("vault is locked".into()));
                        continue;
                    };
                    let mut entry = Entry::new(&name, &username, &url, &password, &notes);
                    entry.totp_secret = totp;
                    match unlocked.add(entry) {
                        Ok(_) => {
                            emit(Event::Info(format!("Saved '{name}'")));
                            emit(Event::Entries(unlocked.entries().to_vec()));
                        }
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
                Cmd::Update { id, name, username, url, password, notes, totp } => {
                    let Some((_, unlocked)) = session.as_mut() else {
                        emit(Event::Error("vault is locked".into()));
                        continue;
                    };
                    let mut patch = EntryPatch::empty();
                    patch.name = Some(name);
                    patch.username = Some(username);
                    patch.url = Some(url);
                    patch.password = password;
                    patch.notes = Some(notes);
                    patch.totp_secret = totp;
                    match unlocked.update(&id, patch) {
                        Ok(()) => {
                            emit(Event::Info("Entry updated".into()));
                            emit(Event::Entries(unlocked.entries().to_vec()));
                        }
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
                Cmd::Delete { id } => {
                    let Some((_, unlocked)) = session.as_mut() else {
                        emit(Event::Error("vault is locked".into()));
                        continue;
                    };
                    match unlocked.delete(&id) {
                        Ok(()) => {
                            emit(Event::Info("Entry deleted".into()));
                            emit(Event::Entries(unlocked.entries().to_vec()));
                        }
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
                Cmd::EncryptFile(path) => {
                    let Some((master, _)) = session.as_ref() else {
                        emit(Event::Error("vault is locked".into()));
                        continue;
                    };
                    match files::encrypt_file(master, &path, None) {
                        Ok(out) => emit(Event::Info(format!("Encrypted → {}", out.display()))),
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
                Cmd::DecryptFile(path) => {
                    let Some((master, _)) = session.as_ref() else {
                        emit(Event::Error("vault is locked".into()));
                        continue;
                    };
                    match files::decrypt_file(master, &path, None) {
                        Ok((out, _)) => {
                            emit(Event::Info(format!("Decrypted → {}", out.display())))
                        }
                        Err(e) => emit(Event::Error(e.to_string())),
                    }
                }
            }
        }
    });

    WorkerHandle { cmd_tx, reply_tx, event_rx }
}

fn do_unlock(
    vault_path: &PathBuf,
    event_tx: &Sender<Event>,
    reply_rx: &Receiver<Reply>,
    ctx: &eframe::egui::Context,
) -> Result<(SecretKey, vault::UnlockedVault)> {
    let locked = Vault::load(vault_path)?;
    let wrapped = locked.wrapped_master_key()?;

    let mut trezor = TrezorManager::connect()?;
    let mut interaction = UiInteraction { event_tx, reply_rx, ctx };
    let master = trezor.decrypt_master_key(&wrapped, &mut interaction)?;
    let unlocked = locked.unlock(&master)?;
    Ok((master, unlocked))
}

struct UiInteraction<'a> {
    event_tx: &'a Sender<Event>,
    reply_rx: &'a Receiver<Reply>,
    ctx: &'a eframe::egui::Context,
}

impl UiInteraction<'_> {
    fn ask(&self, event: Event) -> Result<Reply> {
        let _ = self.event_tx.send(event);
        self.ctx.request_repaint();
        self.reply_rx
            .recv()
            .map_err(|_| Error::Trezor("UI closed during device interaction".into()))
    }
}

impl Interaction for UiInteraction<'_> {
    fn pin(&mut self) -> Result<String> {
        match self.ask(Event::NeedPin)? {
            Reply::Pin(positions) => Ok(positions),
            _ => Err(Error::Trezor("PIN entry cancelled".into())),
        }
    }

    fn passphrase(&mut self) -> Result<Option<String>> {
        match self.ask(Event::NeedPassphrase)? {
            Reply::Passphrase(value) => Ok(value),
            _ => Err(Error::Trezor("passphrase entry cancelled".into())),
        }
    }

    fn notify_button(&mut self) {
        let _ = self.event_tx.send(Event::ButtonWait);
        self.ctx.request_repaint();
    }
}
