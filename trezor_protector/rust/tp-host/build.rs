// Embed the icon and version metadata into tp-host.exe (Windows builds only).
#[cfg(windows)]
fn main() {
    let mut res = winresource::WindowsResource::new();
    res.set_icon("../assets/tp.ico");
    res.set("FileDescription", "TrezorProtector native messaging host for Chrome/Edge");
    res.set("ProductName", "TrezorProtector");
    res.set("OriginalFilename", "tp-host.exe");
    res.set("LegalCopyright", "MIT License");
    res.compile().expect("failed to embed Windows resources");
}

#[cfg(not(windows))]
fn main() {}
