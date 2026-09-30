"""Command-line entry points."""

from __future__ import annotations

import argparse
import sys

from mcp_warden.principals import hash_api_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-warden")
    subcommands = parser.add_subparsers(dest="command", required=True)

    hash_key = subcommands.add_parser(
        "hash-key",
        help="Print the SHA-256 hex digest of a key read from stdin",
    )
    hash_key.set_defaults(handler=_hash_key)

    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler())


def _hash_key() -> int:
    digest = hash_api_key(sys.stdin.buffer.read())
    sys.stdout.write(f"{digest}\n")
    return 0
