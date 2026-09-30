"""Command-line entry points."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_warden.principals import hash_api_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-warden")
    subcommands = parser.add_subparsers(dest="command", required=True)

    hash_key = subcommands.add_parser(
        "hash-key",
        help="Print the SHA-256 hex digest of a key read from stdin",
    )
    hash_key.set_defaults(handler=_hash_key)

    serve = subcommands.add_parser("serve", help="Run the MCP gateway")
    serve.add_argument("-c", "--config", required=True, type=Path)
    serve.add_argument(
        "--allow-all",
        action="store_true",
        help="Test only: allow every tool for an authenticated principal",
    )
    serve.set_defaults(handler=_serve)

    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


def _hash_key(args: argparse.Namespace) -> int:
    del args
    digest = hash_api_key(sys.stdin.buffer.read())
    sys.stdout.write(f"{digest}\n")
    return 0


def _serve(args: argparse.Namespace) -> int:
    from mcp_warden.config import HttpListen, load_config
    from mcp_warden.gateway import build_gateway
    from mcp_warden.principals import load_principals

    config = load_config(args.config)
    directory = load_principals(config.principals_file)
    gateway = build_gateway(config, directory, allow_all=bool(args.allow_all))
    if isinstance(config.listen, HttpListen):
        gateway.run(
            transport="streamable-http",
            host=config.listen.host,
            port=config.listen.port,
            path=config.listen.path,
            show_banner=False,
        )
    else:
        gateway.run(transport="stdio", show_banner=False)
    return 0
