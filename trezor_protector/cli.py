"""
Command-line interface for TrezorProtector.

Commands
--------
  init                 Create a new vault bound to your Trezor device
  status               Show device and vault info
  pw add  <name>       Add a password entry
  pw get  <query>      Show a password entry
  pw list              List all entries
  pw copy <query>      Copy password to clipboard
  pw update <query>    Edit an existing entry
  pw delete <query>    Delete an entry
  pw generate          Generate a strong random password
  file encrypt <path>  Encrypt a file
  file decrypt <path>  Decrypt a .tpenc file
  file view   <path>   Print decrypted text content to terminal
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .crypto import decrypt, encrypt
from .files import decrypt_file, encrypt_file, read_encrypted
from .passwords import generate_password, pack, unpack
from .trezor import TrezorManager
from .vault import DEFAULT_VAULT_PATH, Vault

console = Console()


# ======================================================================
# Shared helpers
# ======================================================================

def _connect_trezor() -> TrezorManager:
    trezor = TrezorManager()
    console.print("[bold yellow]Connecting to Trezor…[/bold yellow]")
    try:
        trezor.connect()
    except ConnectionError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    info = trezor.get_info()
    console.print(
        f"[green]Connected:[/green] {info['model']} "
        f"[dim]'{info['label']}' FW {info['firmware']}[/dim]"
    )
    return trezor


def _unlock(vault_path: Path) -> tuple[TrezorManager, bytes, Vault]:
    """Load vault, connect Trezor, and decrypt the master key."""
    vault = Vault(vault_path)
    try:
        vault.load()
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    trezor = _connect_trezor()

    console.print(
        "[yellow]Requesting master key from device — confirm on your Trezor…[/yellow]"
    )
    try:
        enc_key = vault.get_encrypted_master_key()
        master_key = trezor.decrypt_master_key(enc_key)
    except Exception as exc:
        console.print(f"[red]Could not decrypt master key: {exc}[/red]")
        trezor.disconnect()
        sys.exit(1)

    console.print("[green]Vault unlocked.[/green]\n")
    return trezor, master_key, vault


def _pick_entry(entries: list[dict]) -> Optional[dict]:
    """Interactive menu when a query matches multiple entries."""
    if not entries:
        return None
    if len(entries) == 1:
        return entries[0]

    console.print("[yellow]Multiple matches:[/yellow]")
    for i, e in enumerate(entries, 1):
        console.print(f"  [cyan]{i}.[/cyan] {e['name']}  [dim]{e['username']}[/dim]")

    try:
        choice = click.prompt("Select number", type=int)
    except click.Abort:
        return None

    if 1 <= choice <= len(entries):
        return entries[choice - 1]
    console.print("[red]Invalid selection.[/red]")
    return None


# ======================================================================
# Root group
# ======================================================================

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="TrezorProtector")
@click.option(
    "--vault",
    envvar="TREZOR_PROTECTOR_VAULT",
    default=None,
    metavar="PATH",
    help=f"Vault file path (default: {DEFAULT_VAULT_PATH})",
)
@click.pass_context
def cli(ctx: click.Context, vault: Optional[str]) -> None:
    """TrezorProtector — Password Manager & File Encryption backed by your Trezor."""
    ctx.ensure_object(dict)
    ctx.obj["vault_path"] = Path(vault) if vault else DEFAULT_VAULT_PATH


# ======================================================================
# init
# ======================================================================

@cli.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Create a new vault and bind it to your Trezor device."""
    vault_path: Path = ctx.obj["vault_path"]
    vault = Vault(vault_path)

    if vault.exists:
        # click.confirm does not render rich markup — plain text only.
        if not click.confirm(
            f"Vault already exists at {vault_path}. Overwrite?"
        ):
            console.print("[yellow]Aborted.[/yellow]")
            return

    trezor = _connect_trezor()

    try:
        raw_key = os.urandom(32)
        console.print(
            "[yellow]Encrypting master key — confirm on your Trezor…[/yellow]"
        )
        enc_key = trezor.encrypt_master_key(raw_key)
        vault.create(enc_key)
        console.print(
            Panel(
                f"[green]Vault created at:[/green] {vault_path}\n\n"
                "[dim]Your master key is protected by your Trezor device.\n"
                "Only the device that just confirmed can ever unlock this vault.[/dim]",
                title="[bold green]Vault Initialized[/bold green]",
            )
        )
    except Exception as exc:
        console.print(f"[red]Failed: {exc}[/red]")
    finally:
        trezor.disconnect()


# ======================================================================
# status
# ======================================================================

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show Trezor device and vault status."""
    vault_path: Path = ctx.obj["vault_path"]
    vault = Vault(vault_path)

    t = Table(title="TrezorProtector Status", show_header=True)
    t.add_column("Item", style="cyan", no_wrap=True)
    t.add_column("Value")

    t.add_row("Vault path", str(vault_path))
    if vault.exists:
        vault.load()
        entries = vault.get_passwords()
        t.add_row("Vault status", "[green]Found[/green]")
        t.add_row("Password entries", str(len(entries)))
    else:
        t.add_row("Vault status", "[red]Not found[/red]  (run  init  first)")

    trezor = TrezorManager()
    try:
        trezor.connect()
        info = trezor.get_info()
        t.add_row("Trezor model", info["model"])
        t.add_row("Device label", info["label"])
        t.add_row("Firmware", info["firmware"])
        t.add_row(
            "Initialized",
            "[green]Yes[/green]" if info["initialized"] else "[red]No[/red]",
        )
    except ConnectionError:
        t.add_row("Trezor device", "[red]Not connected[/red]")
    finally:
        trezor.disconnect()

    console.print(t)


# ======================================================================
# pw — password manager
# ======================================================================

@cli.group("pw")
def pw_group() -> None:
    """Password manager commands."""


@pw_group.command("add")
@click.argument("name")
@click.option("--username", "-u", prompt="Username / e-mail")
@click.option("--url", default="", help="Website URL")
@click.option(
    "--password",
    "-p",
    default=None,
    help="Password (prompted if omitted)",
)
@click.option("--notes", "-n", default="", help="Optional notes")
@click.option(
    "--generate",
    "-g",
    is_flag=True,
    default=False,
    help="Auto-generate a strong password",
)
@click.pass_context
def pw_add(
    ctx: click.Context,
    name: str,
    username: str,
    url: str,
    password: Optional[str],
    notes: str,
    generate: bool,
) -> None:
    """Add a new password entry."""
    if generate:
        password = generate_password()
        console.print(f"[green]Generated password:[/green] {password}")
    elif password is None:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        blob = pack(password, notes)
        enc = encrypt(master_key, blob)
        entry_id = vault.add_password(name, username, url, enc)
        console.print(f"[green]Saved:[/green] {name}  [dim](id {entry_id[:8]}…)[/dim]")
    finally:
        trezor.disconnect()


@pw_group.command("list")
@click.option("--search", "-s", default="", help="Filter by name / URL / username")
@click.pass_context
def pw_list(ctx: click.Context, search: str) -> None:
    """List all password entries."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        entries = vault.find_passwords(search) if search else vault.get_passwords()
        if not entries:
            console.print("[yellow]No entries found.[/yellow]")
            return

        t = Table(title=f"Passwords  ({len(entries)} entries)")
        t.add_column("ID", style="dim", width=8)
        t.add_column("Name", style="cyan")
        t.add_column("Username")
        t.add_column("URL", style="blue")
        t.add_column("Updated", style="dim")

        for p in entries:
            t.add_row(
                p["id"][:8],
                p["name"],
                p["username"],
                p.get("url") or "",
                (p.get("updated_at") or "")[:10],
            )
        console.print(t)
    finally:
        trezor.disconnect()


@pw_group.command("get")
@click.argument("query")
@click.option("--show", is_flag=True, help="Print the password in clear text")
@click.pass_context
def pw_get(ctx: click.Context, query: str, show: bool) -> None:
    """Show a password entry."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        entries = vault.find_passwords(query)
        if not entries:
            console.print(f"[red]No entries matching '{query}'.[/red]")
            return

        entry = _pick_entry(entries)
        if not entry:
            return

        pw_data = unpack(decrypt(master_key, bytes.fromhex(entry["encrypted_data"])))

        pw_display = (
            pw_data["password"]
            if show
            else f"[dim]{'•' * min(len(pw_data['password']), 20)}[/dim]  [italic](use --show to reveal)[/italic]"
        )

        lines = [
            f"[bold cyan]Name:[/bold cyan]      {entry['name']}",
            f"[bold cyan]Username:[/bold cyan]  {entry['username']}",
        ]
        if entry.get("url"):
            lines.append(f"[bold cyan]URL:[/bold cyan]       {entry['url']}")
        lines.append(f"[bold cyan]Password:[/bold cyan]  {pw_display}")
        if pw_data.get("notes"):
            lines.append(f"[bold cyan]Notes:[/bold cyan]     {pw_data['notes']}")

        console.print(Panel("\n".join(lines), title=f"[bold]{entry['name']}[/bold]"))
    finally:
        trezor.disconnect()


@pw_group.command("copy")
@click.argument("query")
@click.pass_context
def pw_copy(ctx: click.Context, query: str) -> None:
    """Copy a password to the clipboard."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        entries = vault.find_passwords(query)
        if not entries:
            console.print(f"[red]No entries matching '{query}'.[/red]")
            return

        entry = _pick_entry(entries)
        if not entry:
            return

        pw_data = unpack(decrypt(master_key, bytes.fromhex(entry["encrypted_data"])))

        try:
            import pyperclip  # type: ignore[import]
            pyperclip.copy(pw_data["password"])
            console.print(
                f"[green]Password for '{entry['name']}' copied to clipboard.[/green]"
            )
        except Exception:
            console.print("[yellow]pyperclip unavailable — printing instead:[/yellow]")
            console.print(pw_data["password"])
    finally:
        trezor.disconnect()


@pw_group.command("update")
@click.argument("query")
@click.option("--username", "-u", default=None)
@click.option("--url", default=None)
@click.option("--notes", "-n", default=None)
@click.option(
    "--new-password",
    "new_password",
    is_flag=True,
    help="Prompt for a new password",
)
@click.option("--generate", "-g", is_flag=True, help="Generate a new password")
@click.pass_context
def pw_update(
    ctx: click.Context,
    query: str,
    username: Optional[str],
    url: Optional[str],
    notes: Optional[str],
    new_password: bool,
    generate: bool,
) -> None:
    """Edit an existing password entry."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        entries = vault.find_passwords(query)
        if not entries:
            console.print(f"[red]No entries matching '{query}'.[/red]")
            return

        entry = _pick_entry(entries)
        if not entry:
            return

        pw_data = unpack(decrypt(master_key, bytes.fromhex(entry["encrypted_data"])))

        if generate:
            pw_data["password"] = generate_password()
            console.print(f"[green]New password:[/green] {pw_data['password']}")
        elif new_password:
            pw_data["password"] = click.prompt(
                "New password", hide_input=True, confirmation_prompt=True
            )
        if notes is not None:
            pw_data["notes"] = notes

        enc = encrypt(master_key, pack(pw_data["password"], pw_data.get("notes", "")))
        vault.update_password(
            entry["id"],
            username=username,
            url=url,
            encrypted_data=enc,
        )
        console.print(f"[green]Updated '{entry['name']}'.[/green]")
    finally:
        trezor.disconnect()


@pw_group.command("delete")
@click.argument("query")
@click.pass_context
def pw_delete(ctx: click.Context, query: str) -> None:
    """Delete a password entry."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        entries = vault.find_passwords(query)
        if not entries:
            console.print(f"[red]No entries matching '{query}'.[/red]")
            return

        entry = _pick_entry(entries)
        if not entry:
            return

        if click.confirm(f"Delete '{entry['name']}'?"):
            vault.delete_password(entry["id"])
            console.print(f"[green]Deleted '{entry['name']}'.[/green]")
        else:
            console.print("[yellow]Cancelled.[/yellow]")
    finally:
        trezor.disconnect()


@pw_group.command("generate")
@click.option("--length", "-l", default=20, show_default=True, help="Password length")
@click.option("--no-upper", is_flag=True, help="Exclude uppercase letters")
@click.option("--no-digits", is_flag=True, help="Exclude digits")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols")
@click.option("--count", "-c", default=5, show_default=True, help="How many to generate")
def pw_generate(
    length: int,
    no_upper: bool,
    no_digits: bool,
    no_symbols: bool,
    count: int,
) -> None:
    """Generate strong random passwords (no Trezor required)."""
    console.print("[bold]Generated passwords:[/bold]")
    for i in range(count):
        pw = generate_password(
            length,
            upper=not no_upper,
            digits=not no_digits,
            symbols=not no_symbols,
        )
        console.print(f"  [cyan]{i + 1}.[/cyan] {pw}")


# ======================================================================
# file — file encryption
# ======================================================================

@cli.group("file")
def file_group() -> None:
    """File encryption commands."""


@file_group.command("encrypt")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output path (default: <input>.tpenc)",
)
@click.option(
    "--delete-original",
    is_flag=True,
    default=False,
    help="Securely delete the original after encryption",
)
@click.pass_context
def file_encrypt(
    ctx: click.Context,
    input_file: Path,
    output: Optional[Path],
    delete_original: bool,
) -> None:
    """Encrypt a file with your Trezor key."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        out = encrypt_file(master_key, input_file, output)
        console.print(f"[green]Encrypted:[/green] {input_file} → {out}")

        if delete_original:
            if click.confirm(f"Delete original '{input_file}'?"):
                input_file.unlink()
                console.print(f"[yellow]Deleted:[/yellow] {input_file}")
    except Exception as exc:
        console.print(f"[red]Encryption failed: {exc}[/red]")
    finally:
        trezor.disconnect()


@file_group.command("decrypt")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output path (default: embedded original filename)",
)
@click.pass_context
def file_decrypt(
    ctx: click.Context,
    input_file: Path,
    output: Optional[Path],
) -> None:
    """Decrypt a .tpenc file."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        out, original_name = decrypt_file(master_key, input_file, output)
        console.print(
            f"[green]Decrypted:[/green] {input_file} → {out}  "
            f"[dim](original: {original_name})[/dim]"
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
    except Exception as exc:
        console.print(f"[red]Decryption failed: {exc}[/red]")
    finally:
        trezor.disconnect()


@file_group.command("view")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def file_view(ctx: click.Context, input_file: Path) -> None:
    """Decrypt and print a text file — nothing is written to disk."""
    trezor, master_key, vault = _unlock(ctx.obj["vault_path"])
    try:
        content, original_name = read_encrypted(master_key, input_file)
        try:
            text = content.decode("utf-8")
            console.print(
                Panel(text, title=f"[bold]{original_name}[/bold]  [dim](decrypted)[/dim]")
            )
        except UnicodeDecodeError:
            console.print(
                f"[yellow]Binary file:[/yellow] {original_name}  "
                f"[dim]({len(content):,} bytes)[/dim]"
            )
            console.print("[dim]Use  file decrypt  to save it to disk.[/dim]")
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
    finally:
        trezor.disconnect()
