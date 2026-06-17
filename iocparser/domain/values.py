from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

from iocparser.domain.enums import HASH_IOC_TYPES, IOCType, IOCTypeName, get_custom_ioc_type
from iocparser.domain.sources import normalize_netloc
from iocparser.shared_utils import refang_ioc


@dataclass(frozen=True)
class IndicatorValue:
    """Base value object for normalized indicator values."""

    raw: str

    def canonical(self) -> str:
        """Return the normalized wire value."""
        return refang_ioc(self.raw)


@dataclass(frozen=True)
class DomainValue(IndicatorValue):
    """Domain indicator value."""

    def canonical(self) -> str:
        return super().canonical().strip().lower()


@dataclass(frozen=True)
class HostValue(IndicatorValue):
    """Host indicator value."""

    def canonical(self) -> str:
        return super().canonical().strip().lower()


@dataclass(frozen=True)
class UrlValue(IndicatorValue):
    """URL indicator value."""

    def canonical(self) -> str:
        normalized = super().canonical().strip()
        try:
            parsed = urlparse(normalized)
        except ValueError:
            return normalized
        if parsed.scheme and parsed.netloc:
            # Lowercase the scheme and host (both case-insensitive) while keeping
            # userinfo and the case-sensitive path/query; default an empty path to
            # "/" and drop the client-only fragment so http://X.com, http://x.com/
            # and http://x.com/#frag dedup to one IOC, matching normalize_url_value.
            return parsed._replace(
                scheme=parsed.scheme.lower(),
                netloc=normalize_netloc(parsed.netloc),
                path=parsed.path or "/",
                fragment="",
            ).geturl()
        return normalized


@dataclass(frozen=True)
class HashValue(IndicatorValue):
    """Hash indicator value."""

    def canonical(self) -> str:
        return super().canonical().strip().lower()


@dataclass(frozen=True)
class FuzzyHashValue(IndicatorValue):
    """Case-sensitive fuzzy-hash value (e.g. ssdeep).

    ssdeep digests are ``blocksize:base64:base64`` and the base64 alphabet is
    case-sensitive, so lowercasing (as the hex HashValue does) corrupts the hash and
    would make distinct digests collide. Strip only; preserve case.
    """

    def canonical(self) -> str:
        return super().canonical().strip()


@dataclass(frozen=True)
class IpValue(IndicatorValue):
    """IP indicator value."""

    def canonical(self) -> str:
        value = super().canonical().strip()
        try:
            return str(ip_address(value))
        except ValueError:
            return value


@dataclass(frozen=True)
class EmailValue(IndicatorValue):
    """Email indicator value."""

    def canonical(self) -> str:
        return super().canonical().strip().lower()


def indicator_value_for(ioc_type: IOCType | IOCTypeName | str, raw: str) -> IndicatorValue:
    """Build the correct value object for a given IOC type."""
    custom_type = get_custom_ioc_type(ioc_type)
    if custom_type is not None:
        return indicator_value_for(custom_type.base_type, raw)
    canonical_type = IOCType.from_name(ioc_type)
    if canonical_type == IOCType.DOMAIN:
        return DomainValue(raw)
    if canonical_type == IOCType.HOST:
        return HostValue(raw)
    if canonical_type == IOCType.URL:
        return UrlValue(raw)
    if canonical_type == IOCType.SSDEEP:
        return FuzzyHashValue(raw)
    if canonical_type in HASH_IOC_TYPES:
        return HashValue(raw)
    if canonical_type in {IOCType.IP, IOCType.IPV6}:
        return IpValue(raw)
    if canonical_type == IOCType.EMAIL:
        return EmailValue(raw)
    return IndicatorValue(raw)
