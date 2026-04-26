from __future__ import annotations

from iocparser.domain.enums import IOCType, IOCTypeName, ioc_type_name


def parse_ioc_types(value: str | None) -> tuple[IOCType | IOCTypeName, ...]:
    """Parse a comma-separated IOC type list."""
    if not value:
        return ()
    parsed: list[IOCType | IOCTypeName] = []
    for item in value.split(","):
        stripped = item.strip()
        if stripped:
            parsed.append(IOCType.from_name(stripped))
    return tuple(parsed)


def joined_type_filters(
    include_types: tuple[IOCType | IOCTypeName, ...],
    exclude_types: tuple[IOCType | IOCTypeName, ...],
) -> tuple[str | None, str | None]:
    """Serialize include/exclude IOC filters for plugin-facing APIs."""
    only = ",".join(ioc_type_name(ioc_type) for ioc_type in include_types) if include_types else None
    exclude = ",".join(ioc_type_name(ioc_type) for ioc_type in exclude_types) if exclude_types else None
    return only, exclude
