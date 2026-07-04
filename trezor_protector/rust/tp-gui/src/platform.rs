//! Platform-specific window hardening.
//!
//! This is the only place in the desktop app that uses `unsafe` — the crate
//! is otherwise `#![deny(unsafe_code)]`, and this module opts in explicitly
//! for the two Win32 calls needed to exclude our windows from screen
//! capture.
#![allow(unsafe_code)]

/// Exclude (or re-include) all of this thread's top-level windows from
/// screen capture / remote streaming.
///
/// On Windows this sets `WDA_EXCLUDEFROMCAPTURE`, so screen recorders,
/// remote-desktop tools and most RATs see a blank/black window instead of
/// its contents. It does **not** stop a keylogger or a memory-reading
/// attacker — see ATTACKS.md §4.4.
#[cfg(windows)]
pub fn apply_screen_capture_protection(enabled: bool) {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
    };

    unsafe extern "system" fn set_affinity(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let affinity = windows::Win32::UI::WindowsAndMessaging::WINDOW_DISPLAY_AFFINITY(
            lparam.0 as u32,
        );
        // Ignore failures: some helper windows don't accept an affinity.
        let _ = SetWindowDisplayAffinity(hwnd, affinity);
        TRUE
    }

    let affinity = if enabled { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
    unsafe {
        let _ = EnumThreadWindows(
            GetCurrentThreadId(),
            Some(set_affinity),
            LPARAM(affinity.0 as isize),
        );
    }
}

#[cfg(not(windows))]
pub fn apply_screen_capture_protection(_enabled: bool) {
    // No portable equivalent on X11/Wayland/macOS; left as a no-op.
}
