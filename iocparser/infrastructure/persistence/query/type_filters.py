from __future__ import annotations

from iocparser.domain.type_filters import parse_ioc_types


def normalize_ioc_type_filter(value: tuple[str, ...] | str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(dict.fromkeys(str(ioc_type) for ioc_type in parse_ioc_types(value)))
    normalized: list[str] = []
    for ioc_type in value:
        normalized.extend(str(parsed) for parsed in parse_ioc_types(str(ioc_type)))
    return tuple(dict.fromkeys(normalized))
