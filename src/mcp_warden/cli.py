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

    check = subcommands.add_parser(
        "check-policy",
        help="Validate policy and print the decision matrix",
    )
    check.add_argument("-c", "--config", required=True, type=Path)
    check.set_defaults(handler=_check_policy)

    verify = subcommands.add_parser(
        "verify-log",
        help="Recompute the audit hash chain",
    )
    verify.add_argument("file", type=Path)
    verify.set_defaults(handler=_verify_log)

    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


def _hash_key(args: argparse.Namespace) -> int:
    del args
    digest = hash_api_key(sys.stdin.buffer.read())
    sys.stdout.write(f"{digest}\n")
    return 0


def _check_policy(args: argparse.Namespace) -> int:
    import asyncio

    from mcp_warden.config import ConfigError, load_config
    from mcp_warden.core.native import PolicyError
    from mcp_warden.matrix import render_decision_matrix
    from mcp_warden.principals import PrincipalError, load_principals

    try:
        config = load_config(args.config)
        directory = load_principals(config.principals_file)
        matrix = asyncio.run(render_decision_matrix(config, directory))
    except (ConfigError, PolicyError, PrincipalError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write(matrix)
    return 0


def _verify_log(args: argparse.Namespace) -> int:
    from mcp_warden.core.audit import verify_log

    broken = verify_log(args.file.read_text(encoding="utf-8"))
    if broken is None:
        sys.stdout.write("OK\n")
        return 0
    sys.stdout.write(f"seq {broken}\n")
    return 1


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
