"""hash-key prints the SHA-256 of the exact bytes read from stdin."""

from __future__ import annotations

import subprocess
import sys

# Literal digest of b"test-key". Independent of the implementation under test.
_TEST_KEY_SHA256 = "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
_TEST_KEY_WITH_NEWLINE_SHA256 = "2ea55a1daa794328271c7d1e737710f80b615334281be16369fa99e28983096b"


def _run_hash_key(payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "mcp_warden", "hash-key"],
        input=payload,
        capture_output=True,
        check=False,
    )


def test_hash_key_prints_sha256_of_exact_stdin_bytes() -> None:
    result = _run_hash_key(b"test-key")

    assert result.returncode == 0
    assert result.stdout == f"{_TEST_KEY_SHA256}\n".encode()
    assert result.stderr == b""


def test_hash_key_does_not_strip_a_trailing_newline() -> None:
    result = _run_hash_key(b"test-key\n")

    assert result.returncode == 0
    assert result.stdout == f"{_TEST_KEY_WITH_NEWLINE_SHA256}\n".encode()


def test_hash_key_rejects_extra_arguments() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "mcp_warden", "hash-key", "not-stdin"],
        input=b"test-key",
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0


def test_missing_command_is_rejected() -> None:
    result = subprocess.run([sys.executable, "-m", "mcp_warden"], capture_output=True, check=False)
    assert result.returncode != 0
