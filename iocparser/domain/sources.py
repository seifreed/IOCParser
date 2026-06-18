from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from iocparser.domain.enums import SourceKind


def normalize_url_value(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit(
        (
            parts.scheme.lower(),
            normalize_netloc(parts.netloc),
            parts.path or "/",
            parts.query,
            "",
        ),
    )


def normalize_netloc(netloc: str) -> str:
    """Lowercase the host (and port) while preserving case-sensitive userinfo."""
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)
        return f"{userinfo}@{host_port.lower()}"
    return netloc.lower()


def _require_str(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string-like, got {type(value).__name__}")
    return value


@dataclass(frozen=True)
class Source:
    """Input source metadata."""

    kind: SourceKind
    value: str
    original_url: str | None = None
    normalized_url: str | None = None
    mime_type: str | None = None
    input_size: int | None = None
    content_hash: str | None = None
    fingerprint: str | None = None

    @classmethod
    def from_raw(
        cls,
        kind: str,
        value: str,
        *,
        original_url: str | None = None,
        normalized_url: str | None = None,
        mime_type: str | None = None,
        input_size: int | None = None,
        content_hash: str | None = None,
        fingerprint: str | None = None,
    ) -> Source:
        """Build a Source from wire values."""
        source_kind = SourceKind.from_name(_require_str(kind, field="kind"))
        raw_value = _require_str(value, field="value")
        original = original_url
        normalized = normalized_url
        if source_kind is SourceKind.URL:
            original = original or raw_value
            normalized = normalize_url_value(normalized) or normalize_url_value(raw_value)
        return cls(
            kind=source_kind,
            value=raw_value,
            original_url=original,
            normalized_url=normalized,
            mime_type=mime_type,
            input_size=input_size,
            content_hash=content_hash,
            fingerprint=fingerprint,
        )
