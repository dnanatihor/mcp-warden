"""Principals loader and constant-time key lookup."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import pytest

from mcp_warden.principals import PrincipalDirectory, PrincipalError, hash_api_key, load_principals

_ANALYST_KEY = "analyst-secret"
_STEWARD_KEY = "steward-secret"


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _write_principals(path: Path) -> None:
    path.write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{_sha(_ANALYST_KEY)}"
    attributes: {{roles: [analyst], team: finance, clearance: internal}}
  - id: steward-agent
    key_sha256: "{_sha(_STEWARD_KEY).upper()}"
    attributes: {{roles: [steward], team: governance, clearance: confidential}}
""",
        encoding="utf-8",
    )


def test_hash_api_key_is_sha256_hex() -> None:
    assert (
        hash_api_key(b"test-key")
        == "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
    )


def test_load_principals_keeps_attributes_and_normalises_hashes(tmp_path: Path) -> None:
    path = tmp_path / "principals.yaml"
    _write_principals(path)

    directory = load_principals(path)
    analyst = directory.lookup(_ANALYST_KEY)
    steward = directory.lookup(_STEWARD_KEY)

    assert analyst is not None
    assert analyst.id == "analyst-agent"
    assert analyst.key_sha256 == _sha(_ANALYST_KEY)
    assert analyst.attributes == {"roles": ["analyst"], "team": "finance", "clearance": "internal"}
    assert steward is not None
    assert steward.id == "steward-agent"
    assert steward.key_sha256 == _sha(_STEWARD_KEY)


def test_unknown_key_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "principals.yaml"
    _write_principals(path)

    assert load_principals(path).lookup("wrong-key") is None


def test_lookup_compares_every_principal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "principals.yaml"
    _write_principals(path)
    directory = load_principals(path)
    comparisons: list[tuple[str, str]] = []
    original = hmac.compare_digest

    def _record(a: object, b: object) -> bool:
        comparisons.append((str(a), str(b)))
        return original(str(a), str(b))

    monkeypatch.setattr("mcp_warden.principals.hmac.compare_digest", _record)

    found = directory.lookup(_ANALYST_KEY)

    assert found is not None
    assert found.id == "analyst-agent"
    assert len(comparisons) == 2


def test_duplicate_principal_id_is_rejected(tmp_path: Path) -> None:
    digest = _sha("k")
    path = tmp_path / "principals.yaml"
    path.write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{digest}"
    attributes: {{}}
  - id: analyst-agent
    key_sha256: "{_sha("other")}"
    attributes: {{}}
""",
        encoding="utf-8",
    )

    with pytest.raises(PrincipalError, match="duplicate principal id"):
        load_principals(path)


def test_duplicate_key_hash_is_rejected(tmp_path: Path) -> None:
    digest = _sha("k")
    path = tmp_path / "principals.yaml"
    path.write_text(
        f"""
principals:
  - id: analyst-agent
    key_sha256: "{digest}"
    attributes: {{}}
  - id: steward-agent
    key_sha256: "{digest}"
    attributes: {{}}
""",
        encoding="utf-8",
    )

    with pytest.raises(PrincipalError, match="duplicate key hash"):
        load_principals(path)


def test_malformed_hash_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "principals.yaml"
    path.write_text(
        """
principals:
  - id: analyst-agent
    key_sha256: "not-a-hash"
    attributes: {}
""",
        encoding="utf-8",
    )

    with pytest.raises(PrincipalError):
        load_principals(path)


def test_directory_exposes_principals_in_file_order(tmp_path: Path) -> None:
    path = tmp_path / "principals.yaml"
    _write_principals(path)
    directory: PrincipalDirectory = load_principals(path)

    assert [principal.id for principal in directory.principals] == [
        "analyst-agent",
        "steward-agent",
    ]
