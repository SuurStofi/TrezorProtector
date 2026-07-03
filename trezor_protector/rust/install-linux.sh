#!/usr/bin/env bash
# TrezorProtector Linux installer: builds the workspace, installs binaries
# to ~/.local/bin, sets up udev rules and (optionally) the Chrome native
# messaging host.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Checking build prerequisites"
command -v cargo >/dev/null || {
    echo "rustup/cargo not found — install from https://rustup.rs" >&2; exit 1; }
command -v cc >/dev/null || {
    echo "C compiler not found — e.g. sudo apt install build-essential" >&2; exit 1; }
pkg-config --exists libusb-1.0 2>/dev/null || \
    echo "note: libusb-1.0 dev headers not found (sudo apt install libusb-1.0-0-dev);" \
         "the vendored copy will be built instead"

echo "==> Building release binaries"
cargo build --release

echo "==> Installing to ~/.local/bin"
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/tp target/release/tp-host "$HOME/.local/bin/"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "    add ~/.local/bin to your PATH" ;;
esac

echo "==> Installing udev rules (needs sudo; skip with Ctrl+C if already set up by Trezor Suite)"
if [ ! -e /etc/udev/rules.d/51-trezor.rules ]; then
    sudo cp assets/51-trezor.rules /etc/udev/rules.d/
    sudo udevadm control --reload-rules
    sudo udevadm trigger
else
    echo "    /etc/udev/rules.d/51-trezor.rules already present — leaving it"
fi

if [ -n "${1:-}" ]; then
    echo "==> Registering Chrome native messaging host for extension $1"
    "$HOME/.local/bin/tp-host" install --extension-id "$1"
else
    echo "==> To enable the Chrome extension later:"
    echo "    tp-host install --extension-id <id from chrome://extensions>"
fi

echo "Done. Try: tp status"
