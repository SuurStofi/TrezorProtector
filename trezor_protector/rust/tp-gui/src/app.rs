//! The full vault manager window.

use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, Color32, RichText};
use tp_core::passwords::{self, GenerateOptions};
use tp_core::settings::Settings;
use tp_core::totp::Totp;
use tp_core::vault::Entry;

use crate::worker::{self, Cmd, Event, Reply, WorkerHandle};

const ACCENT: Color32 = Color32::from_rgb(39, 176, 108);

/// A small deterministic palette for the generated site tiles.
const TILE_COLORS: [Color32; 8] = [
    Color32::from_rgb(39, 176, 108),
    Color32::from_rgb(70, 130, 220),
    Color32::from_rgb(200, 120, 40),
    Color32::from_rgb(170, 90, 200),
    Color32::from_rgb(210, 80, 100),
    Color32::from_rgb(40, 170, 180),
    Color32::from_rgb(150, 150, 60),
    Color32::from_rgb(110, 110, 200),
];

/// Registrable-ish label + first letter for an entry's icon tile.
fn site_label(entry: &Entry) -> (char, Color32) {
    let basis = if !entry.url.is_empty() { &entry.url } else { &entry.name };
    let host = basis
        .rsplit("://")
        .next()
        .unwrap_or(basis)
        .trim_start_matches("www.");
    let ch = host
        .chars()
        .find(|c| c.is_alphanumeric())
        .unwrap_or('?')
        .to_ascii_uppercase();
    let mut h: u32 = 2166136261;
    for b in host.bytes() {
        h = (h ^ b as u32).wrapping_mul(16777619);
    }
    (ch, TILE_COLORS[(h as usize) % TILE_COLORS.len()])
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Registrable-ish domain used to group entries into folders.
fn domain_key(entry: &Entry) -> String {
    let basis = if !entry.url.is_empty() { &entry.url } else { &entry.name };
    let host = basis.rsplit("://").next().unwrap_or(basis);
    let host = host.split('/').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_start_matches("www.").to_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() >= 2 {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else if host.is_empty() {
        entry.name.to_lowercase()
    } else {
        host
    }
}

/// Render one selectable entry row (tile + label). Returns true if clicked.
fn entry_row(
    ui: &mut egui::Ui,
    entry: &Entry,
    label: &str,
    selected: Option<&str>,
    show_icons: bool,
) -> bool {
    let is_sel = selected == Some(entry.id.as_str());
    ui.horizontal(|ui| {
        if show_icons {
            let (ch, color) = site_label(entry);
            draw_tile(ui, ch, color);
        }
        let text = if entry.username.is_empty() || label == entry.username {
            trunc(label, 30)
        } else {
            format!("{}\n    {}", trunc(label, 26), trunc(&entry.username, 28))
        };
        ui.add(egui::SelectableLabel::new(is_sel, text)).clicked()
    })
    .inner
}

fn draw_tile(ui: &mut egui::Ui, ch: char, color: Color32) {
    let size = egui::vec2(22.0, 22.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.painter().rect_filled(rect, 5.0, color);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        ch,
        egui::FontId::proportional(13.0),
        Color32::WHITE,
    );
}

#[derive(Default)]
enum Modal {
    #[default]
    None,
    Pin {
        buffer: String,
    },
    Passphrase {
        value: String,
    },
    ButtonWait,
    ConfirmDelete {
        id: String,
        name: String,
    },
    Settings,
}

#[derive(Default, Clone)]
struct EntryForm {
    id: Option<String>, // None = add
    name: String,
    username: String,
    url: String,
    password: String,
    password_changed: bool,
    notes: String,
    totp: String,
    totp_changed: bool,
}

pub struct ManagerApp {
    worker: WorkerHandle,
    unlocked: bool,
    busy: bool,
    entries: Vec<Entry>,
    search: String,
    selected: Option<String>,
    reveal: bool,
    status: (String, Color32),
    modal: Modal,
    form: Option<EntryForm>,
    gen_length: u32,
    gen_symbols: bool,
    gen_passphrase: bool,
    gen_output: String,
    last_activity: Instant,
    settings: Settings,
    vault_path: std::path::PathBuf,
    last_vault_mtime: Option<std::time::SystemTime>,
    last_sync_check: Instant,
    applied_capture_protection: Option<bool>,
}

impl ManagerApp {
    pub fn new(ctx: &egui::Context) -> Self {
        Self {
            worker: worker::spawn(ctx.clone()),
            unlocked: false,
            busy: false,
            entries: Vec::new(),
            search: String::new(),
            selected: None,
            reveal: false,
            status: ("Vault is locked".into(), Color32::GRAY),
            modal: Modal::None,
            form: None,
            gen_length: 20,
            gen_symbols: true,
            gen_passphrase: false,
            gen_output: String::new(),
            last_activity: Instant::now(),
            settings: Settings::load_default(),
            vault_path: std::env::var_os("TREZOR_PROTECTOR_VAULT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(tp_core::vault::default_path),
            last_vault_mtime: None,
            last_sync_check: Instant::now(),
            applied_capture_protection: None,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.worker.event_rx.try_recv() {
            match event {
                Event::NeedPin => self.modal = Modal::Pin { buffer: String::new() },
                Event::NeedPassphrase => self.modal = Modal::Passphrase { value: String::new() },
                Event::ButtonWait => self.modal = Modal::ButtonWait,
                Event::Unlocked(entries) => {
                    self.entries = entries;
                    self.unlocked = true;
                    self.busy = false;
                    self.modal = Modal::None;
                    self.status = (
                        format!("Unlocked — {} entries", self.entries.len()),
                        ACCENT,
                    );
                    self.last_activity = Instant::now();
                    self.last_vault_mtime = tp_core::vault::file_mtime(&self.vault_path);
                }
                Event::Entries(entries) => {
                    self.entries = entries;
                    self.form = None;
                    // Our own write (or an accepted reload) updated the file;
                    // re-baseline so the poll doesn't reload again pointlessly.
                    self.last_vault_mtime = tp_core::vault::file_mtime(&self.vault_path);
                }
                Event::DeviceGone => {
                    if self.settings.lock_on_disconnect && self.unlocked {
                        let _ = self.worker.cmd_tx.send(Cmd::Lock);
                        self.status =
                            ("Trezor unplugged — vault locked".into(), Color32::from_rgb(224, 82, 82));
                    }
                }
                Event::Locked => {
                    self.unlocked = false;
                    self.entries.clear();
                    self.selected = None;
                    self.form = None;
                    self.reveal = false;
                    self.status = ("Vault is locked".into(), Color32::GRAY);
                }
                Event::Error(e) => {
                    self.busy = false;
                    self.modal = Modal::None;
                    self.status = (e, Color32::from_rgb(224, 82, 82));
                }
                Event::Info(msg) => self.status = (msg, ACCENT),
            }
        }
    }

    fn copy_autoclear(&mut self, text: &str, what: &str) {
        let value = text.to_string();
        std::thread::spawn(move || {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if cb.set_text(value.clone()).is_ok() {
                    std::thread::sleep(Duration::from_secs(30));
                    if cb.get_text().map(|t| t == value).unwrap_or(false) {
                        let _ = cb.set_text(String::new());
                    }
                }
            }
        });
        self.status = (format!("{what} copied — clipboard clears in 30 s"), ACCENT);
    }

    /// Called after a stored secret is revealed or copied. When
    /// "require confirmation for every operation" is on, this re-locks the
    /// vault so the next secret access needs a fresh device unlock.
    fn after_secret_access(&mut self) {
        if self.settings.pin_every_operation {
            let _ = self.worker.cmd_tx.send(Cmd::Lock);
            self.status = (
                "Locked (per-operation confirmation is on)".into(),
                Color32::GRAY,
            );
        }
    }

    fn generate(&mut self) {
        self.gen_output = if self.gen_passphrase {
            passwords::generate_passphrase(6, "-")
                .map(|p| p.to_string())
                .unwrap_or_default()
        } else {
            passwords::generate(&GenerateOptions {
                length: self.gen_length as usize,
                symbols: self.gen_symbols,
                ..Default::default()
            })
            .map(|p| p.to_string())
            .unwrap_or_default()
        };
    }

    // -- views ---------------------------------------------------------------

    fn locked_view(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("TrezorProtector");
            ui.add_space(8.0);
            ui.label("The vault unlocks only with a confirmation on your Trezor.");
            ui.add_space(20.0);
            let button = egui::Button::new(
                RichText::new(if self.busy { "Connecting…" } else { "🔓 Unlock with Trezor" })
                    .size(16.0),
            )
            .min_size([220.0, 40.0].into())
            .fill(ACCENT.linear_multiply(0.25));
            if ui.add_enabled(!self.busy, button).clicked() {
                self.busy = true;
                self.status = ("Connect and confirm on your device…".into(), Color32::GRAY);
                let _ = self.worker.cmd_tx.send(Cmd::Unlock);
            }
        });
    }

    fn entry_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search…")
                    .desired_width(ui.available_width() - 34.0),
            );
            if ui.button("＋").on_hover_text("Add entry").clicked() {
                self.form = Some(EntryForm::default());
                self.selected = None;
            }
        });
        ui.add_space(6.0);

        let query = self.search.to_lowercase();
        let matches: Vec<Entry> = self
            .entries
            .iter()
            .filter(|e| {
                query.is_empty()
                    || e.name.to_lowercase().contains(&query)
                    || e.username.to_lowercase().contains(&query)
                    || e.url.to_lowercase().contains(&query)
            })
            .cloned()
            .collect();

        // Group by registrable domain so a site with several accounts
        // collapses into one folder.
        let mut groups: std::collections::BTreeMap<String, Vec<Entry>> = Default::default();
        for e in matches {
            groups.entry(domain_key(&e)).or_default().push(e);
        }
        for v in groups.values_mut() {
            v.sort_by_key(|e| e.username.to_lowercase());
        }

        let show_icons = self.settings.show_site_icons;
        let searching = !query.is_empty();
        let mut clicked: Option<String> = None;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (domain, items) in &groups {
                if items.len() == 1 {
                    // Singleton: render the entry directly, no folder.
                    let e = &items[0];
                    if entry_row(ui, e, &e.name, self.selected.as_deref(), show_icons) {
                        clicked = Some(e.id.clone());
                    }
                } else {
                    // Multi-account site: a collapsible folder.
                    let header = egui::CollapsingHeader::new(
                        RichText::new(format!("🗂  {domain}  ({})", items.len())).strong(),
                    )
                    .id_salt(("domain", domain))
                    .default_open(searching);
                    header.show(ui, |ui| {
                        for e in items {
                            let label = if e.username.is_empty() { e.name.clone() } else { e.username.clone() };
                            if entry_row(ui, e, &label, self.selected.as_deref(), show_icons) {
                                clicked = Some(e.id.clone());
                            }
                        }
                    });
                }
            }
        });

        if let Some(id) = clicked {
            self.selected = Some(id);
            self.reveal = false;
            self.form = None;
        }
    }

    fn details_panel(&mut self, ui: &mut egui::Ui) {
        // Editing / adding takes over the panel.
        if self.form.is_some() {
            self.form_view(ui);
            return;
        }

        let Some(entry) = self
            .selected
            .as_ref()
            .and_then(|id| self.entries.iter().find(|e| &e.id == id))
            .cloned()
        else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Select an entry, or ＋ to add one").weak());
            });
            return;
        };

        ui.heading(&entry.name);
        if !entry.url.is_empty() {
            ui.label(RichText::new(&entry.url).color(Color32::from_rgb(110, 160, 255)));
        }
        ui.add_space(10.0);

        let mut secret_copied = false;
        egui::Grid::new("detail-grid").num_columns(3).spacing([10.0, 8.0]).show(ui, |ui| {
            ui.label(RichText::new("Username").strong());
            ui.label(&entry.username);
            if ui.small_button("Copy").clicked() {
                self.copy_autoclear(&entry.username, "Username");
            }
            ui.end_row();

            ui.label(RichText::new("Password").strong());
            if self.reveal {
                ui.label(RichText::new(&entry.password).monospace());
            } else {
                ui.label(RichText::new("•".repeat(entry.password.chars().count().min(18))));
            }
            ui.horizontal(|ui| {
                if ui.small_button(if self.reveal { "Hide" } else { "Show" }).clicked() {
                    self.reveal = !self.reveal;
                }
                if ui.small_button("Copy").clicked() {
                    self.copy_autoclear(&entry.password, "Password");
                    secret_copied = true;
                }
            });
            ui.end_row();

            if let Some(secret) = &entry.totp_secret {
                ui.label(RichText::new("2FA code").strong());
                match Totp::from_base32(secret).and_then(|t| t.now()) {
                    Ok(code) => {
                        ui.label(
                            RichText::new(format!(
                                "{}  ({}s)",
                                code.code, code.seconds_remaining
                            ))
                            .monospace()
                            .color(ACCENT)
                            .size(16.0),
                        );
                        if ui.small_button("Copy").clicked() {
                            self.copy_autoclear(&code.code, "2FA code");
                            secret_copied = true;
                        }
                    }
                    Err(e) => {
                        ui.label(RichText::new(e.to_string()).weak());
                        ui.label("");
                    }
                }
                ui.end_row();
            }

            if !entry.notes.is_empty() {
                ui.label(RichText::new("Notes").strong());
                ui.label(&entry.notes);
                ui.label("");
                ui.end_row();
            }

            ui.label(RichText::new("Updated").strong());
            ui.label(RichText::new(&entry.updated_at).weak());
            ui.label("");
            ui.end_row();
        });

        if !entry.history.is_empty() {
            ui.add_space(6.0);
            ui.collapsing(format!("Password history ({})", entry.history.len()), |ui| {
                for item in &entry.history {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&item.replaced_at).weak());
                        ui.label(RichText::new(&item.password).monospace());
                    });
                }
            });
        }

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            if ui.button("✏ Edit").clicked() {
                self.form = Some(EntryForm {
                    id: Some(entry.id.clone()),
                    name: entry.name.clone(),
                    username: entry.username.clone(),
                    url: entry.url.clone(),
                    password: String::new(),
                    password_changed: false,
                    notes: entry.notes.clone(),
                    totp: entry.totp_secret.clone().unwrap_or_default(),
                    totp_changed: false,
                });
            }
            if ui.button("🗑 Delete").clicked() {
                self.modal = Modal::ConfirmDelete {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                };
            }
        });

        if secret_copied {
            self.after_secret_access();
        }
    }

    fn form_view(&mut self, ui: &mut egui::Ui) {
        let mut submit = false;
        let mut cancel = false;
        let mut generate_into_form = false;

        {
            let form = self.form.as_mut().unwrap();
            ui.heading(if form.id.is_some() { "Edit entry" } else { "New entry" });
            ui.add_space(8.0);

            egui::Grid::new("form-grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut form.name);
                ui.end_row();
                ui.label("Username");
                ui.text_edit_singleline(&mut form.username);
                ui.end_row();
                ui.label("URL");
                ui.text_edit_singleline(&mut form.url);
                ui.end_row();
                ui.label("Password");
                ui.horizontal(|ui| {
                    let hint = if form.id.is_some() && !form.password_changed {
                        "(unchanged)"
                    } else {
                        ""
                    };
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut form.password)
                                .password(false)
                                .hint_text(hint),
                        )
                        .changed()
                    {
                        form.password_changed = true;
                    }
                    if ui.small_button("Generate").clicked() {
                        generate_into_form = true;
                    }
                });
                ui.end_row();
                ui.label("2FA secret");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut form.totp)
                            .hint_text("base32 or otpauth:// (optional)"),
                    )
                    .changed()
                {
                    form.totp_changed = true;
                }
                ui.end_row();
                ui.label("Notes");
                ui.text_edit_multiline(&mut form.notes);
                ui.end_row();
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let can_save =
                    !form.name.is_empty() && (form.id.is_some() || !form.password.is_empty());
                if ui.add_enabled(can_save, egui::Button::new("💾 Save")).clicked() {
                    submit = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        }

        if generate_into_form {
            if let Ok(pw) = passwords::generate(&GenerateOptions::default()) {
                let form = self.form.as_mut().unwrap();
                form.password = pw.to_string();
                form.password_changed = true;
            }
        }
        if cancel {
            self.form = None;
        }
        if submit {
            let form = self.form.clone().unwrap();
            let totp_value =
                if form.totp.trim().is_empty() { None } else { Some(form.totp.trim().to_string()) };
            let cmd = match form.id {
                None => Cmd::Add {
                    name: form.name,
                    username: form.username,
                    url: form.url,
                    password: form.password,
                    notes: form.notes,
                    totp: totp_value,
                },
                Some(id) => Cmd::Update {
                    id,
                    name: form.name,
                    username: form.username,
                    url: form.url,
                    password: form.password_changed.then_some(form.password),
                    notes: form.notes,
                    totp: form.totp_changed.then_some(totp_value),
                },
            };
            let _ = self.worker.cmd_tx.send(cmd);
        }
    }

    fn tools_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("🔒 Encrypt files…")
                .on_hover_text("Import one or more files and encrypt each with your Trezor key")
                .clicked()
            {
                if let Some(paths) = rfd::FileDialog::new().pick_files() {
                    for path in paths {
                        let _ = self.worker.cmd_tx.send(Cmd::EncryptFile(path));
                    }
                }
            }
            if ui
                .button("🎭 Encrypt as…")
                .on_hover_text("Encrypt one file to a name/extension you choose (e.g. notes.pdf)")
                .clicked()
            {
                if let Some(src) = rfd::FileDialog::new().pick_file() {
                    let suggested = src
                        .file_name()
                        .map(|n| format!("{}.pdf", n.to_string_lossy()))
                        .unwrap_or_else(|| "encrypted.pdf".into());
                    if let Some(dst) = rfd::FileDialog::new().set_file_name(suggested).save_file() {
                        let _ = self.worker.cmd_tx.send(Cmd::EncryptFileAs { src, dst });
                    }
                }
            }
            if ui.button("🔓 Decrypt files…").clicked() {
                if let Some(paths) = rfd::FileDialog::new().pick_files() {
                    for path in paths {
                        let _ = self.worker.cmd_tx.send(Cmd::DecryptFile(path));
                    }
                }
            }
            ui.separator();
            ui.label("Generator:");
            ui.checkbox(&mut self.gen_passphrase, "passphrase");
            if !self.gen_passphrase {
                ui.add(egui::DragValue::new(&mut self.gen_length).range(8..=64));
                ui.checkbox(&mut self.gen_symbols, "symbols");
            }
            if ui.button("Generate").clicked() {
                self.generate();
            }
            if !self.gen_output.is_empty() {
                ui.label(RichText::new(&self.gen_output).monospace());
                if ui.small_button("Copy").clicked() {
                    let value = self.gen_output.clone();
                    self.copy_autoclear(&value, "Generated password");
                }
            }
        });
    }

    fn modals(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut reply: Option<Reply> = None;
        let mut delete: Option<String> = None;

        match &mut self.modal {
            Modal::None => return,
            Modal::Pin { buffer } => {
                egui::Window::new("Trezor PIN")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Click the positions shown on your device:");
                        ui.add_space(6.0);
                        for row in [["7", "8", "9"], ["4", "5", "6"], ["1", "2", "3"]] {
                            ui.horizontal(|ui| {
                                for pos in row {
                                    if ui
                                        .add_sized([48.0, 40.0], egui::Button::new("•"))
                                        .clicked()
                                        && buffer.len() < 9
                                    {
                                        buffer.push_str(pos);
                                    }
                                }
                            });
                        }
                        ui.add_space(4.0);
                        ui.label(RichText::new("• ".repeat(buffer.len())).size(16.0));
                        ui.horizontal(|ui| {
                            if ui.button("⌫").clicked() {
                                buffer.pop();
                            }
                            if ui
                                .add_enabled(!buffer.is_empty(), egui::Button::new("Confirm"))
                                .clicked()
                            {
                                reply = Some(Reply::Pin(buffer.clone()));
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                reply = Some(Reply::Cancel);
                                close = true;
                            }
                        });
                    });
            }
            Modal::Passphrase { value } => {
                egui::Window::new("Passphrase")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        if ui.button("Enter on the device (recommended)").clicked() {
                            reply = Some(Reply::Passphrase(None));
                            close = true;
                        }
                        ui.add_space(6.0);
                        ui.label("…or type it here:");
                        ui.add(egui::TextEdit::singleline(value).password(true));
                        ui.horizontal(|ui| {
                            if ui.button("Use").clicked() && !value.is_empty() {
                                reply = Some(Reply::Passphrase(Some(value.clone())));
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                reply = Some(Reply::Cancel);
                                close = true;
                            }
                        });
                    });
            }
            Modal::ButtonWait => {
                egui::Window::new("Confirm on device")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("Press the button on your Trezor to continue…");
                        ui.add_space(4.0);
                        ui.spinner();
                    });
            }
            Modal::ConfirmDelete { id, name } => {
                let id = id.clone();
                let name = name.clone();
                egui::Window::new("Delete entry")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!("Delete '{name}'? This cannot be undone."));
                        ui.horizontal(|ui| {
                            if ui.button("Delete").clicked() {
                                delete = Some(id.clone());
                                close = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::Settings => {
                let mut changed = false;
                let mut s = self.settings.clone();
                egui::Window::new("⚙ Settings")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.set_min_width(340.0);
                        changed |= ui
                            .checkbox(&mut s.pin_every_operation, "Require device confirmation for every reveal / copy")
                            .changed();
                        changed |= ui
                            .checkbox(&mut s.lock_on_disconnect, "Lock immediately when the Trezor is unplugged")
                            .changed();
                        changed |= ui
                            .checkbox(&mut s.relock_after_manual_lock, "Require unlock again after a manual Lock")
                            .changed();
                        changed |= ui
                            .checkbox(&mut s.screen_capture_protection, "Anti-RAT: exclude windows from screen capture")
                            .changed();
                        changed |= ui
                            .checkbox(&mut s.show_site_icons, "Show site icon tiles")
                            .changed();

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Auto-lock after (minutes, 0 = never):");
                            changed |= ui
                                .add(egui::DragValue::new(&mut s.auto_lock_minutes).range(0..=240))
                                .changed();
                        });
                        ui.horizontal(|ui| {
                            ui.label("Clipboard auto-clear (seconds, 0 = never):");
                            changed |= ui
                                .add(egui::DragValue::new(&mut s.clipboard_clear_seconds).range(0..=600))
                                .changed();
                        });

                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(
                                "Recovery phrase (for re-binding a new Trezor) is managed from the CLI: `tp vault recovery-setup`.",
                            )
                            .weak()
                            .size(11.0),
                        );
                        if s.screen_capture_protection {
                            ui.label(
                                RichText::new(
                                    "Windows are now hidden from screen capture / remote streaming.",
                                )
                                .weak()
                                .size(11.0),
                            );
                        }

                        ui.add_space(8.0);
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
                if changed {
                    self.settings = s;
                    let _ = self.settings.save_default();
                }
            }
        }

        if let Some(reply) = reply {
            let _ = self.worker.reply_tx.send(reply);
        }
        if let Some(id) = delete {
            self.selected = None;
            let _ = self.worker.cmd_tx.send(Cmd::Delete { id });
        }
        if close {
            self.modal = Modal::None;
        }
    }
}

impl eframe::App for ManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        // Apply screen-capture protection when the setting changes (the
        // window exists by now, so this takes effect immediately).
        let want = self.settings.screen_capture_protection;
        if self.applied_capture_protection != Some(want) {
            crate::platform::apply_screen_capture_protection(want);
            self.applied_capture_protection = Some(want);
        }

        // Track activity for auto-lock; tick once per second for TOTP.
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        if self.unlocked {
            ctx.request_repaint_after(Duration::from_secs(1));
            let minutes = self.settings.auto_lock_minutes;
            if minutes > 0 && self.last_activity.elapsed() > Duration::from_secs(minutes * 60) {
                let _ = self.worker.cmd_tx.send(Cmd::Lock);
            }
            // Pick up writes made by the browser extension host (or any other
            // process) roughly once a second.
            if self.last_sync_check.elapsed() > Duration::from_millis(900) {
                self.last_sync_check = Instant::now();
                let current = tp_core::vault::file_mtime(&self.vault_path);
                if current != self.last_vault_mtime {
                    self.last_vault_mtime = current;
                    let _ = self.worker.cmd_tx.send(Cmd::Reload);
                }
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🛡 TrezorProtector").strong().size(15.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙").on_hover_text("Settings").clicked() {
                        self.modal = Modal::Settings;
                    }
                    if self.unlocked && ui.button("🔒 Lock").clicked() {
                        let _ = self.worker.cmd_tx.send(Cmd::Lock);
                    }
                    ui.add(egui::Label::new(
                        RichText::new(&self.status.0).color(self.status.1),
                    ).truncate());
                });
            });
        });

        if self.unlocked {
            egui::TopBottomPanel::bottom("tools").show(ctx, |ui| {
                ui.add_space(4.0);
                self.tools_bar(ui);
                ui.add_space(4.0);
            });
            egui::SidePanel::left("list")
                .resizable(true)
                .default_width(250.0)
                .width_range(190.0..=360.0)
                .show(ctx, |ui| {
                    ui.add_space(6.0);
                    self.entry_list(ui);
                });
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.details_panel(ui);
                    });
            });
        } else {
            egui::CentralPanel::default().show(ctx, |ui| self.locked_view(ui));
        }

        self.modals(ctx);
    }
}
