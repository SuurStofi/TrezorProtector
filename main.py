#!/usr/bin/env python3
"""
TrezorProtector — entry point.

Usage:
    python main.py --help
    python main.py init
    python main.py status
    python main.py pw add github.com
    python main.py pw list
    python main.py pw get github
    python main.py pw copy github
    python main.py pw update github --generate
    python main.py pw delete github
    python main.py pw generate --length 24
    python main.py file encrypt secrets.txt
    python main.py file decrypt secrets.txt.tpenc
    python main.py file view   secrets.txt.tpenc
"""

import sys

# Friendly error if dependencies are missing
try:
    import click  # noqa: F401
    import rich   # noqa: F401
except ImportError:
    print(
        "Missing dependencies.\n"
        "Run:  pip install -r requirements.txt\n",
        file=sys.stderr,
    )
    sys.exit(1)

from trezor_protector.cli import cli

if __name__ == "__main__":
    cli()
