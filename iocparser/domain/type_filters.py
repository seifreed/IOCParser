from __future__ import annotations

from iocparser.domain.enums import HASH_IOC_TYPES, IOCType, IOCTypeName, ioc_type_name

# Category words that select a whole family of IOC types rather than one type.
# "hashes" must expand to every hash type; aliasing it to a single type silently
# dropped md5/sha1/sha512/ssdeep/imphash from --only/--exclude.
# Keys must stay equal to enums.CATEGORY_FILTER_NAMES (the registration guard), or a
# custom type named after a new category would silently become unselectable; a test
# asserts the two stay in sync.
_CATEGORY_ALIASES: dict[str, tuple[IOCType, ...]] = {
    "hashes": tuple(sorted(HASH_IOC_TYPES, key=lambda ioc_type: ioc_type.value)),
}


def parse_ioc_types(value: str | None) -> tuple[IOCType | IOCTypeName, ...]:
    """Parse a comma-separated IOC type list, expanding category words."""
    if not value:
        return ()
    parsed: list[IOCType | IOCTypeName] = []
    for item in value.split(","):
        stripped = item.strip()
        if not stripped:
            continue
        category = _CATEGORY_ALIASES.get(stripped.lower())
        if category is not None:
            parsed.extend(category)
        else:
            parsed.append(IOCType.from_name(stripped))
    return tuple(parsed)


def joined_type_filters(
    include_types: tuple[IOCType | IOCTypeName, ...],
    exclude_types: tuple[IOCType | IOCTypeName, ...],
) -> tuple[str | None, str | None]:
    """Serialize include/exclude IOC filters for plugin-facing APIs."""
    only = (
        ",".join(ioc_type_name(ioc_type) for ioc_type in include_types) if include_types else None
    )
    exclude = (
        ",".join(ioc_type_name(ioc_type) for ioc_type in exclude_types) if exclude_types else None
    )
    return only, exclude
