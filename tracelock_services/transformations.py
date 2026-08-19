"""Phase 8 safe payload transformations."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class TransformationResult:
    transformed_body: dict[str, Any] | list[Any]
    redacted_fields: tuple[str, ...]
    transformation_types: tuple[str, ...]
    body_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "redacted_fields": list(self.redacted_fields),
            "transformation_types": list(self.transformation_types),
            "body_sha256": self.body_sha256,
        }


def redact_to_permitted_fields(
    body: dict[str, Any] | list[Any],
    permitted_fields: tuple[str, ...],
) -> TransformationResult:
    """Rebuild a JSON payload containing only policy-permitted leaf paths."""

    original = copy.deepcopy(body)
    transformed = _filter_value(original, "", permitted_fields)
    if not isinstance(transformed, (dict, list)):
        transformed = {}
    original_paths = set(_leaf_paths(original))
    transformed_paths = set(_leaf_paths(transformed))
    redacted = tuple(sorted(original_paths - transformed_paths))
    encoded = json.dumps(
        transformed,
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
    ).encode()
    return TransformationResult(
        transformed,
        redacted,
        ("filter",),
        hashlib.sha256(encoded).hexdigest(),
    )


def ensure_removed_values_absent(
    original: dict[str, Any] | list[Any],
    transformed: dict[str, Any] | list[Any],
    redacted_fields: tuple[str, ...],
) -> bool:
    """Ensure values removed from sensitive paths do not survive elsewhere."""

    original_values = _path_values(original)
    transformed_serialized = json.dumps(
        transformed,
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=True,
    )
    for path in redacted_fields:
        value = original_values.get(path)
        if value is None:
            continue
        encoded_value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        if encoded_value.strip('"') and encoded_value.strip('"') in transformed_serialized:
            return False
    return True


def _filter_value(value: Any, prefix: str, permitted: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            filtered = _filter_value(child, path, permitted)
            if filtered is not _OMIT:
                result[key] = filtered
        return result
    if isinstance(value, list):
        wildcard = f"{prefix}[*]" if prefix else "[*]"
        list_result: list[Any] = []
        for child in value:
            filtered = _filter_value(child, wildcard, permitted)
            if filtered is not _OMIT:
                list_result.append(filtered)
        return list_result
    if _path_is_permitted(prefix, permitted):
        return value
    return _OMIT


class _Omit:
    pass


_OMIT = _Omit()


def _path_is_permitted(path: str, permitted: tuple[str, ...]) -> bool:
    return any(
        expected == path
        or expected.endswith("[*]") and path.startswith(expected[:-3])
        for expected in permitted
    )


def _leaf_paths(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, dict):
        collected: list[str] = []
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            collected.extend(_leaf_paths(child, path))
        return collected
    if isinstance(value, list):
        wildcard = f"{prefix}[*]" if prefix else "[*]"
        collected = []
        for child in value:
            collected.extend(_leaf_paths(child, wildcard))
        return collected or [wildcard]
    return [prefix or "$"]


def _path_values(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_path_values(child, path))
        return result
    if isinstance(value, list):
        wildcard = f"{prefix}[*]" if prefix else "[*]"
        result = {}
        for child in value:
            result.update(_path_values(child, wildcard))
        return result
    return {prefix or "$": value}
