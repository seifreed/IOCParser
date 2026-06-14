from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from iocparser.domain.models import ExtractionOptions, IOCType, IOCTypeName
from iocparser.domain.type_filters import parse_ioc_types
from iocparser.errors import ValidationError
from iocparser.shared_utils import parse_bool_token

INTEGER_VALUE_REQUIRED = "{field_name} requires an integer value"


def int_arg_value(raw_value: object, field_name: str) -> int:
    """Coerce an argparse value to int, rejecting bools and non-numeric input."""
    if isinstance(raw_value, bool) or not isinstance(raw_value, int | str):
        raise ValidationError(INTEGER_VALUE_REQUIRED.format(field_name=field_name))
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValidationError(INTEGER_VALUE_REQUIRED.format(field_name=field_name)) from exc


def namespace_value(args: argparse.Namespace, field_name: str) -> object | None:
    """Return the raw attribute value for ``field_name`` from an argparse namespace."""
    namespace = cast("Mapping[str, object]", vars(args))
    return namespace.get(field_name)


def int_value(value: object, *, default: int = 0) -> int:
    """Leniently coerce a scalar value to int, returning ``default`` on failure."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            try:
                return int(stripped)
            except ValueError:
                return default
    return default


def get_str_arg(args: argparse.Namespace, name: str, default: str = "") -> str:
    """Get string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return str(value) if value is not None else default


def get_bool_arg(args: argparse.Namespace, name: str, default: bool = False) -> bool:
    """Get boolean argument from argparse namespace."""
    value: object = getattr(args, name, None)
    if value is None:
        return default
    if isinstance(value, str):
        parsed = parse_bool_token(value)
        return parsed if parsed is not None else False
    return bool(value)


def get_int_arg(args: argparse.Namespace, name: str, default: int = 0) -> int:
    """Get integer argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return int(str(value)) if value is not None else default


def get_list_arg(args: argparse.Namespace, name: str) -> list[str]:
    """Get list argument from argparse namespace."""
    value: object = getattr(args, name, None)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def get_optional_str_arg(args: argparse.Namespace, name: str) -> str | None:
    """Get optional string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return str(value) if value is not None else None


def parse_string_filters(value: object) -> tuple[str, ...]:
    """Parse comma-separated filter values from a CLI argument."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for entry in value:
            items.extend(part.strip() for part in str(entry).split(",") if part.strip())
        return tuple(items)
    return tuple(part.strip() for part in str(value).split(",") if part.strip())


@dataclass(frozen=True)
class ProcessingOptions:
    """CLI processing options facade."""

    file_type: str | None = None
    defang: bool = True
    check_warnings: bool = True
    force_update: bool = False
    include_types: tuple[IOCType | IOCTypeName, ...] = ()
    exclude_types: tuple[IOCType | IOCTypeName, ...] = ()

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> ProcessingOptions:
        """Create ProcessingOptions from command line arguments."""
        return cls(
            file_type=get_optional_str_arg(args, "type"),
            defang=not get_bool_arg(args, "no_defang"),
            check_warnings=not get_bool_arg(args, "no_check_warnings"),
            force_update=get_bool_arg(args, "force_update"),
            include_types=parse_ioc_types(get_optional_str_arg(args, "only")),
            exclude_types=parse_ioc_types(get_optional_str_arg(args, "exclude")),
        )

    def to_domain(self) -> ExtractionOptions:
        """Convert CLI options into application/domain options."""
        return ExtractionOptions(
            file_type=self.file_type,
            defang=self.defang,
            check_warnings=self.check_warnings,
            force_update=self.force_update,
            include_types=self.include_types,
            exclude_types=self.exclude_types,
        )
