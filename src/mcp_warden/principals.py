"""Principal loading and API-key lookup.

Keys are stored only as SHA-256 hex digests. Lookup hashes the presented key
and compares that digest with every stored digest using ``hmac.compare_digest``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_HASH_RE = re.compile(r"[0-9a-f]{64}")
Scalar = str | int | float | bool
AttributeValue = Scalar | list[Scalar]


class PrincipalError(Exception):
    """A principals file cannot be loaded."""


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    key_sha256: str
    attributes: dict[str, AttributeValue] = Field(default_factory=dict)

    @field_validator("key_sha256")
    @classmethod
    def _normalise_hash(cls, value: str) -> str:
        lowered = value.strip().lower()
        if _HASH_RE.fullmatch(lowered) is None:
            raise ValueError("key_sha256 must be 64 hex characters")
        return lowered


class _PrincipalsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principals: list[Principal]


class PrincipalDirectory:
    """Loaded principals, with constant-time key lookup."""

    def __init__(self, principals: tuple[Principal, ...]) -> None:
        self._principals = principals

    @property
    def principals(self) -> tuple[Principal, ...]:
        return self._principals

    def lookup(self, api_key: str) -> Principal | None:
        digest = hash_api_key(api_key.encode("utf-8"))
        found: Principal | None = None
        for principal in self._principals:
            if hmac.compare_digest(principal.key_sha256, digest):
                found = principal
        return found


def hash_api_key(key: bytes) -> str:
    """SHA-256 hex digest of the exact key bytes. No whitespace is stripped."""
    return hashlib.sha256(key).hexdigest()


def load_principals(path: Path) -> PrincipalDirectory:
    raw = _read_mapping(path)
    try:
        parsed = _PrincipalsFile.model_validate(raw)
    except ValidationError as exc:
        raise PrincipalError(_public_validation_message(exc)) from None
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for principal in parsed.principals:
        if principal.id in seen_ids:
            raise PrincipalError(f"duplicate principal id: {principal.id}")
        if principal.key_sha256 in seen_hashes:
            raise PrincipalError(f"duplicate key hash for principal id: {principal.id}")
        seen_ids.add(principal.id)
        seen_hashes.add(principal.key_sha256)
    return PrincipalDirectory(tuple(parsed.principals))


def _read_mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise PrincipalError("principals file must be a mapping")
    return loaded


def _public_validation_message(exc: ValidationError) -> str:
    parts = [".".join(str(item) for item in error["loc"]) for error in exc.errors()]
    return "invalid principals file: " + ", ".join(parts)
