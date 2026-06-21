import logging
import re as _re
import sys
from collections.abc import Callable, Iterable, Mapping
from threading import Lock
from typing import Protocol

from iocparser.errors import TypeValidationError, ValidationError


def lazy_singleton[T](holder: list[T], lock: Lock, factory: Callable[[], T]) -> T:
    """Return a process-wide singleton, building it once via double-checked locking."""
    if not holder:
        with lock:
            if not holder:
                holder.append(factory())
    return holder[0]


class _RollbackUnit(Protocol):
    def rollback(self) -> None: ...


class _CloseUnit(Protocol):
    def close(self) -> object: ...


def rollback_and_log(unit: _RollbackUnit, *, logger: logging.Logger, message: str) -> None:
    try:
        unit.rollback()
    except Exception:
        logger.exception(message)


def close_and_log(unit: _CloseUnit, *, logger: logging.Logger, message: str) -> None:
    primary_exc = sys.exc_info()[1]
    try:
        unit.close()
    except Exception:
        if primary_exc is None:
            raise
        logger.exception(message)


TRUE_BOOL_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
FALSE_BOOL_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off"})
VALID_DIFF_ONLY_VALUES: frozenset[str] = frozenset({"all", "added", "removed"})
INVALID_DIFF_ONLY_ERROR = "Invalid diff_only: {value}"
VALID_SEVERITIES: frozenset[str] = frozenset({"informational", "low", "medium", "high"})
INVALID_SEVERITY_ERROR = "Invalid severity: {value}"
INVALID_STRING_FILTER_ERROR = "Invalid filter value: {value}"


def parse_bool_token(value: str) -> bool | None:
    """Map a string to True/False using the canonical boolean vocabularies.

    A blank/whitespace-only string is treated as False; unrecognized tokens
    return None so callers can decide whether to fall back to a default or raise.
    """
    normalized = value.strip().lower()
    if normalized in TRUE_BOOL_VALUES:
        return True
    if normalized == "" or normalized in FALSE_BOOL_VALUES:
        return False
    return None


def normalize_tokens(items: Iterable[str]) -> tuple[str, ...]:
    """Strip and lowercase each item, dropping blanks and preserving order."""
    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise TypeValidationError("token", "string", item)
        stripped = item.strip()
        if stripped:
            normalized.append(stripped.lower())
    return tuple(normalized)


def normalize_metadata_values(metadata: Mapping[str, object]) -> dict[str, int | str | None]:
    """Coerce each metadata value to int/str/None, rejecting arbitrary objects."""
    normalized: dict[str, int | str | None] = {}
    for key, value in metadata.items():
        if (
            (isinstance(value, int) and not isinstance(value, bool))
            or isinstance(value, str)
            or value is None
        ):
            normalized[key] = value
            continue
        subject = f"metadata value for {key}"
        raise TypeValidationError(subject, "int/string/None", value)
    return normalized


def parse_string_filters(value: object) -> tuple[str, ...]:
    """Split comma-separated filter values, stripping blanks.

    Accepts ``None`` (yields an empty tuple), a single scalar, or a
    list/tuple of scalars whose items are each split on commas.
    """
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for entry in value:
            if not isinstance(entry, str):
                raise ValidationError(INVALID_STRING_FILTER_ERROR.format(value=entry))
            items.extend(part.strip() for part in entry.split(",") if part.strip())
        return tuple(items)
    if not isinstance(value, str):
        raise ValidationError(INVALID_STRING_FILTER_ERROR.format(value=value))
    return tuple(part.strip() for part in value.split(",") if part.strip())


def validated_severity_filters(value: object) -> tuple[str, ...]:
    """Split, normalize, and validate comma-separated severity filters."""
    normalized: list[str] = []
    for severity in parse_string_filters(value):
        candidate = severity.strip().lower()
        if candidate not in VALID_SEVERITIES:
            raise ValidationError(INVALID_SEVERITY_ERROR.format(value=severity))
        normalized.append(candidate)
    return tuple(normalized)


def validated_diff_only(value: str | None) -> str:
    """Normalize and validate a diff-only selector, defaulting None to "all"."""
    if value is None:
        return "all"
    normalized = value.strip().lower()
    if not normalized:
        return "all"
    if normalized not in VALID_DIFF_ONLY_VALUES:
        raise ValidationError(INVALID_DIFF_ONLY_ERROR.format(value=value))
    return normalized


DEFANG_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("(:)", ":"),
    ("{:}", ":"),
    ("[@]", "@"),
    ("[@ ]", "@"),
    ("(@)", "@"),
    ("{@}", "@"),
    ("[://]", "://"),
    ("(://)", "://"),
    ("{://}", "://"),
    ("[//]", "//"),
    ("{//}", "//"),
    ("[/]", "/"),
    ("{/}", "/"),
    ("hxxp://", "http://"),
    ("hxxps://", "https://"),
    ("hXXp://", "http://"),
    ("hXXps://", "https://"),
    ("h__p://", "http://"),
    ("h__ps://", "https://"),
    ("fxp://", "ftp://"),
    ("sfxp://", "sftp://"),
)


def _dedup_key(item: str | dict[str, str]) -> str:
    if isinstance(item, dict):
        return str(sorted(item.items())).lower()
    return str(item).lower()


def dedup_case_insensitive(items: list[str]) -> list[str]:
    """Drop case-insensitive duplicates from a string list, preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def deduplicate_iocs(
    iocs: dict[str, list[str | dict[str, str]]],
) -> dict[str, list[str | dict[str, str]]]:
    """Remove duplicate IOCs while preserving order (case-insensitive)."""
    deduplicated: dict[str, list[str | dict[str, str]]] = {}
    for ioc_type, ioc_list in iocs.items():
        unique_items: list[str | dict[str, str]] = []
        seen_keys: set[str] = set()
        for item in ioc_list:
            key = _dedup_key(item)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_items.append(item)
        deduplicated[ioc_type] = unique_items
    return deduplicated


def deduplicate_iocs_with_state(
    new_iocs: dict[str, list[str]],
    seen_iocs: dict[str, set[str]],
    *,
    key_func: Callable[[str, str], str] | None = None,
) -> dict[str, list[str]]:
    """Remove duplicate IOCs using external state tracking.

    Without ``key_func`` the dedup key is a blanket lowercase (case-insensitive).
    Pass ``key_func(ioc_type, value)`` to supply a per-type canonical key so
    case-sensitive types (URL paths, ssdeep digests) are not wrongly merged --
    a blanket lowercase silently dropped case-distinct URLs, matching the bug
    already fixed in the domain ``grouped_iocs``/``canonical_by_type`` dedup.
    """
    unique_iocs: dict[str, list[str]] = {}
    for ioc_type, ioc_list in new_iocs.items():
        unique = []
        type_seen = seen_iocs.setdefault(ioc_type, set())
        for ioc in ioc_list:
            key = key_func(ioc_type, ioc) if key_func is not None else ioc.lower()
            if key not in type_seen:
                type_seen.add(key)
                unique.append(ioc)
        if unique:
            unique_iocs[ioc_type] = unique
    return unique_iocs


# Bracket/symbol defangs (start with a non-letter, e.g. "[://]") are applied as
# literal replacements; only the alphabetic scheme spellings (hxxp://, fxp://, ...)
# are routed through the case-insensitive regex pass below. Filtering on "://"
# alone wrongly skipped the bracketed "[://]" form, leaving such URLs defanged.
_NON_SCHEME_REPLACEMENTS: tuple[tuple[str, str], ...] = tuple(
    (search, replacement) for search, replacement in DEFANG_REPLACEMENTS if not search[:1].isalpha()
)

_COMPILED_SCHEME_PATTERNS: tuple[tuple[_re.Pattern[str], str], ...] = tuple(
    (_re.compile(_re.escape(pattern), _re.IGNORECASE), replacement)
    for pattern, replacement in (
        ("hxxps://", "https://"),
        ("hxxp://", "http://"),
        ("h__ps://", "https://"),
        ("h__p://", "http://"),
        ("sfxp://", "sftp://"),
        ("fxp://", "ftp://"),
    )
)


# Word-style dot defangs (evil[dot]com, evil(dot)com) are common in threat reports.
# Matched case-insensitively since reports mix "[dot]" and "[DOT]"; the symbol forms
# above stay literal because they have no case to vary.
WORD_DOT_PATTERN = _re.compile(r"\[dot\]|\(dot\)|\{dot\}", _re.IGNORECASE)


def refang_ioc(value: str) -> str:
    """Normalize common defanged IOC variants back to canonical form."""
    cleaned = WORD_DOT_PATTERN.sub(".", value)
    for search, replacement in _NON_SCHEME_REPLACEMENTS:
        cleaned = cleaned.replace(search, replacement)
    for compiled_pattern, replacement in _COMPILED_SCHEME_PATTERNS:
        cleaned = compiled_pattern.sub(replacement, cleaned)
    return cleaned
