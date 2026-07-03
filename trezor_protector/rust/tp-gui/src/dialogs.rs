//! Small always-on-top dialog windows used by the native messaging host
//! (`tp-gui pin` / `passphrase` / `connect`).
//!
//! Protocol with the parent process: the result is printed as one line on
//! stdout and the exit code signals cancel (0 = value provided, 1 =
//! cancelled). The Trezor PIN dialog collects *matrix positions*, never
//! actual digits — the layout only exists on the device screen.

use eframe::egui;

fn options(width: f32, height: f32) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([width, height])
            .with_resizable(false)
            .with_always_on_top(),
        centered: true,
        ..Default::default()
    }
}

/// Common outcome slot: None until the user decides.
type Outcome = std::rc::Rc<std::cell::RefCell<Option<Option<String>>>>;

fn finish(ctx: &egui::Context, outcome: &Outcome, value: Option<String>) {
    *outcome.borrow_mut() = Some(value);
    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
}

// ---------------------------------------------------------------------------
// PIN matrix
// ---------------------------------------------------------------------------

struct PinApp {
    buffer: String,
    outcome: Outcome,
}

impl eframe::App for PinApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(6.0);
                ui.heading("Trezor PIN");
                ui.label("Click the positions shown on your device:");
                ui.add_space(10.0);

                let grid = [["7", "8", "9"], ["4", "5", "6"], ["1", "2", "3"]];
                for row in grid {
                    ui.horizontal(|ui| {
                        // Center the 3-button row.
                        let total = 3.0 * 56.0 + 2.0 * 8.0;
                        let pad = (ui.available_width() - total).max(0.0) / 2.0;
                        ui.add_space(pad);
                        for pos in row {
                            if ui
                                .add_sized([56.0, 48.0], egui::Button::new(
                                    egui::RichText::new("•").size(22.0),
                                ))
                                .clicked()
                                && self.buffer.len() < 9
                            {
                                self.buffer.push_str(pos);
                            }
                        }
                    });
                    ui.add_space(8.0);
                }

                ui.label(
                    egui::RichText::new(if self.buffer.is_empty() {
                        " ".to_string()
                    } else {
                        "• ".repeat(self.buffer.len())
                    })
                    .size(18.0),
                );
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    let total = 200.0;
                    let pad = (ui.available_width() - total).max(0.0) / 2.0;
                    ui.add_space(pad);
                    if ui.button("⌫").clicked() {
                        self.buffer.pop();
                    }
                    let ok = ui.add_enabled(
                        !self.buffer.is_empty(),
                        egui::Button::new("Confirm"),
                    );
                    if ok.clicked() {
                        finish(ctx, &self.outcome, Some(self.buffer.clone()));
                    }
                    if ui.button("Cancel").clicked() {
                        finish(ctx, &self.outcome, None);
                    }
                });
            });
        });
    }
}

pub fn run_pin() -> ! {
    let outcome: Outcome = Default::default();
    let out2 = outcome.clone();
    let result = eframe::run_native(
        "TrezorProtector — PIN",
        options(270.0, 330.0),
        Box::new(move |_| Ok(Box::new(PinApp { buffer: String::new(), outcome: out2 }))),
    );
    conclude(result, outcome)
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

struct PassphraseApp {
    value: String,
    outcome: Outcome,
}

impl eframe::App for PassphraseApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(6.0);
                ui.heading("Passphrase");
                ui.add_space(8.0);
                if ui.button("Enter on the device (recommended)").clicked() {
                    // Empty string = on-device entry.
                    finish(ctx, &self.outcome, Some(String::new()));
                }
                ui.add_space(10.0);
                ui.label("…or type it here:");
                ui.add(egui::TextEdit::singleline(&mut self.value).password(true));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let pad = (ui.available_width() - 130.0).max(0.0) / 2.0;
                    ui.add_space(pad);
                    if ui.button("Use").clicked() && !self.value.is_empty() {
                        finish(ctx, &self.outcome, Some(self.value.clone()));
                    }
                    if ui.button("Cancel").clicked() {
                        finish(ctx, &self.outcome, None);
                    }
                });
            });
        });
    }
}

pub fn run_passphrase() -> ! {
    let outcome: Outcome = Default::default();
    let out2 = outcome.clone();
    let result = eframe::run_native(
        "TrezorProtector — Passphrase",
        options(320.0, 210.0),
        Box::new(move |_| {
            Ok(Box::new(PassphraseApp { value: String::new(), outcome: out2 }))
        }),
    );
    conclude(result, outcome)
}

// ---------------------------------------------------------------------------
// Connect prompt
// ---------------------------------------------------------------------------

struct ConnectApp {
    outcome: Outcome,
}

impl eframe::App for ConnectApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                ui.heading("Connect your Trezor");
                ui.add_space(6.0);
                ui.label("No device found. Plug in your Trezor and close");
                ui.label("Trezor Suite if it is holding the connection.");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let pad = (ui.available_width() - 140.0).max(0.0) / 2.0;
                    ui.add_space(pad);
                    if ui.button("Retry").clicked() {
                        finish(ctx, &self.outcome, Some("retry".into()));
                    }
                    if ui.button("Cancel").clicked() {
                        finish(ctx, &self.outcome, None);
                    }
                });
            });
        });
    }
}

pub fn run_connect() -> ! {
    let outcome: Outcome = Default::default();
    let out2 = outcome.clone();
    let result = eframe::run_native(
        "TrezorProtector",
        options(320.0, 170.0),
        Box::new(move |_| Ok(Box::new(ConnectApp { outcome: out2 }))),
    );
    conclude(result, outcome)
}

// ---------------------------------------------------------------------------

fn conclude(result: eframe::Result, outcome: Outcome) -> ! {
    if result.is_err() {
        std::process::exit(2);
    }
    let value = outcome.borrow_mut().take().flatten();
    match value {
        Some(v) => {
            println!("{v}");
            std::process::exit(0);
        }
        None => std::process::exit(1),
    }
}
