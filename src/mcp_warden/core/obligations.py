"""Pure obligation transforms from SPEC.md §6.

``strip_inferences`` calls ``epienv.enforce`` when that package is installed.
Otherwise a Level 2 envelope is updated to the same documented effect:
inferences cleared, ``inference_permitted`` false, and the withheld notice set.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Protocol

from mcp_warden.core.models import OBLIGATION_ORDER, Obligation

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().\-]{8,}\d(?!\w)")
_CARD = re.compile(r"(?<!\w)(?:\d[ -]?){13,19}(?!\w)")
_WITHHELD_NOTICE = "AI inferences were withheld by policy."
_REDACTED = "«redacted»"


class Span(Protocol):
    start: int
    end: int
    type: str


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    type: str


class PiiDetector(Protocol):
    def find(self, text: str) -> list[Match]: ...


@dataclass(frozen=True)
class ObligationResult:
    value: Any
    applied: tuple[str, ...]
    not_applicable: tuple[str, ...]


class DefaultPiiDetector:
    """Email, phone, and Luhn-checked card-like numbers."""

    def find(self, text: str) -> list[Match]:
        found: list[Match] = []
        found.extend(Match(item.start(), item.end(), "email") for item in _EMAIL.finditer(text))
        found.extend(
            Match(item.start(), item.end(), "card")
            for item in _CARD.finditer(text)
            if _luhn(re.sub(r"\D", "", item.group()))
        )
        card_spans = {(item.start, item.end) for item in found if item.type == "card"}
        found.extend(
            Match(item.start(), item.end(), "phone")
            for item in _PHONE.finditer(text)
            if _digit_count(item.group()) >= 10 and (item.start(), item.end()) not in card_spans
        )
        return _drop_overlaps(found)


def apply_obligations(value: Any, obligations: tuple[Obligation, ...]) -> ObligationResult:
    current = value
    applied: list[str] = []
    skipped: list[str] = []
    ordered = tuple(sorted(obligations, key=lambda item: OBLIGATION_ORDER.index(item.type)))
    for obligation in ordered:
        if obligation.type == "redact_fields":
            current = _redact(current, obligation.paths)
            applied.append(obligation.type)
        elif obligation.type == "strip_inferences":
            current, did_apply = _strip(current)
            (applied if did_apply else skipped).append(obligation.type)
        elif obligation.type == "mask_pii":
            detector = _detector(obligation)
            current = _map_strings(current, lambda text, detector=detector: _mask(text, detector))
            applied.append(obligation.type)
        elif obligation.type == "max_items" and obligation.n is not None:
            current, truncated = _truncate(current, obligation.n)
            applied.append(obligation.type)
            if not truncated:
                pass
    return ObligationResult(value=current, applied=tuple(applied), not_applicable=tuple(skipped))


def _strip(value: Any) -> tuple[Any, bool]:
    if _is_level2(value):
        return _strip_level2(value), True
    if _contains_level1(value):
        return _remove_inferred(value), True
    return value, False


def _is_level2(value: Any) -> bool:
    return (
        isinstance(value, dict) and "envelope_version" in value and "inference_permitted" in value
    )


def _contains_level1(value: Any) -> bool:
    if isinstance(value, dict):
        if "epistemic_layer" in value and "envelope_version" not in value:
            return True
        return any(_contains_level1(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_level1(item) for item in value)
    return False


def _strip_level2(document: dict[str, Any]) -> dict[str, Any]:
    module = _epienv()
    if module is not None:
        policy = module.InferencePolicy(permitted=False)
        envelope = module.Envelope.model_validate(document)
        enforced = module.enforce(envelope, policy)
        dumped = enforced.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    updated = dict(document)
    updated["ai_inferences"] = []
    updated["inference_permitted"] = False
    updated["governance_notice"] = _WITHHELD_NOTICE
    return updated


def _remove_inferred(value: Any) -> Any:
    if isinstance(value, list):
        return [_remove_inferred(item) for item in value if not _is_inferred(item)]
    if isinstance(value, dict):
        if _is_inferred(value):
            return None
        return {
            key: _remove_inferred(item) for key, item in value.items() if not _is_inferred(item)
        }
    return value


def _is_inferred(value: Any) -> bool:
    return isinstance(value, dict) and value.get("epistemic_layer") == "inferred"


def _redact(value: Any, paths: tuple[str, ...]) -> Any:
    if not isinstance(value, dict | list):
        return value
    current = json.loads(json.dumps(value))
    for path in paths:
        _apply_json_path(current, _json_path_tokens(path))
    return current


def _json_path_tokens(path: str) -> tuple[str | int | None, ...]:
    if not path.startswith("$"):
        return ()
    rest = path[1:]
    tokens: list[str | int | None] = []
    while rest:
        if rest.startswith("."):
            rest = rest[1:]
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", rest)
            if match is None:
                break
            tokens.append(match.group())
            rest = rest[match.end() :]
            continue
        if rest.startswith("["):
            end = rest.find("]")
            if end < 0:
                break
            inner = rest[1:end]
            rest = rest[end + 1 :]
            tokens.append(None if inner == "*" else int(inner))
            continue
        break
    return tuple(tokens)


def _apply_json_path(node: Any, tokens: tuple[str | int | None, ...]) -> None:
    if not tokens:
        return
    key = tokens[0]
    rest = tokens[1:]
    if isinstance(node, dict) and isinstance(key, str) and key in node:
        if rest:
            _apply_json_path(node[key], rest)
        else:
            node[key] = _REDACTED
        return
    if isinstance(node, list) and isinstance(key, int) and 0 <= key < len(node):
        if rest:
            _apply_json_path(node[key], rest)
        else:
            node[key] = _REDACTED
        return
    if key is None and isinstance(node, list):
        for index, item in enumerate(node):
            if rest:
                _apply_json_path(item, rest)
            else:
                node[index] = _REDACTED


def _truncate(value: Any, limit: int) -> tuple[Any, bool]:
    if not isinstance(value, dict):
        return value, False
    updated = dict(value)
    truncated = False
    for key, item in updated.items():
        if isinstance(item, list) and len(item) > limit:
            updated[key] = item[:limit]
            truncated = True
    if truncated:
        updated["_warden_truncated"] = True
    return updated, truncated


def _map_strings(value: Any, transform: Any) -> Any:
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, list):
        return [_map_strings(item, transform) for item in value]
    if isinstance(value, dict):
        return {key: _map_strings(item, transform) for key, item in value.items()}
    return value


def _mask(text: str, detector: PiiDetector) -> str:
    matches = detector.find(text)
    updated = text
    for match in sorted(matches, key=lambda item: item.start, reverse=True):
        token = f"«{_token_name(match.type)}»"
        updated = updated[: match.start] + token + updated[match.end :]
    return updated


def _token_name(kind: str) -> str:
    if kind in {"email", "phone", "card"}:
        return kind
    return kind


def _detector(obligation: Obligation) -> PiiDetector:
    bharat = _bharat_detector()
    if bharat is not None and not obligation.detectors:
        return bharat
    return DefaultPiiDetector()


def _epienv() -> Any:
    try:
        return import_module("epienv")
    except ImportError:
        return None


def _bharat_detector() -> PiiDetector | None:
    try:
        module = import_module("bharat_pii_bench")
    except ImportError:
        return None
    detector = getattr(module, "detector", None)
    if detector is None:
        return None
    return detector if hasattr(detector, "find") else None


def _digit_count(value: str) -> int:
    return sum(character.isdigit() for character in value)


def _luhn(number: str) -> bool:
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    total = 0
    parity = len(number) % 2
    for index, character in enumerate(number):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _drop_overlaps(matches: list[Match]) -> list[Match]:
    ordered = sorted(matches, key=lambda item: (item.start, -(item.end - item.start)))
    accepted: list[Match] = []
    cursor = -1
    for match in ordered:
        if match.start < cursor:
            continue
        accepted.append(match)
        cursor = match.end
    return accepted


def render_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
