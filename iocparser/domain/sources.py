from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from iocparser.domain.enums import SourceKind


def normalize_url_value(value: str | None) -> str | None:
    if not value:
        return None
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            parts.query,
            "",
        ),
    )


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
        source_kind = SourceKind.from_name(kind)
        normalized = normalized_url
        if source_kind is SourceKind.URL:
            normalized = normalize_url_value(normalized) or normalize_url_value(value)
        return cls(
            kind=source_kind,
            value=value,
            original_url=original_url,
            normalized_url=normalized,
            mime_type=mime_type,
            input_size=input_size,
            content_hash=content_hash,
            fingerprint=fingerprint,
        )
