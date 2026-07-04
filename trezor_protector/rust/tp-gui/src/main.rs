//! TrezorProtector desktop UI.
//!
//! Modes:
//! * `tp-gui` — full vault manager window
//! * `tp-gui pin` — PIN-matrix dialog (used by tp-host); prints the selected
//!   positions to stdout
//! * `tp-gui passphrase` — passphrase dialog (empty line = on-device)
//! * `tp-gui connect` — "connect your Trezor" retry prompt

#![forbid(unsafe_code)]
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod dialogs;
mod worker;

fn main() -> eframe::Result {
    match std::env::args().nth(1).as_deref() {
        Some("pin") => dialogs::run_pin(),
        Some("passphrase") => dialogs::run_passphrase(),
        Some("connect") => dialogs::run_connect(),
        _ => {
            let options = eframe::NativeOptions {
                viewport: eframe::egui::ViewportBuilder::default()
                    .with_inner_size([900.0, 600.0])
                    .with_min_inner_size([760.0, 480.0]),
                centered: true,
                ..Default::default()
            };
            eframe::run_native(
                "TrezorProtector",
                options,
                Box::new(|cc| Ok(Box::new(app::ManagerApp::new(&cc.egui_ctx)))),
            )
        }
    }
}
