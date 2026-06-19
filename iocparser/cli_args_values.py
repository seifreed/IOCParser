from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from iocparser.domain.models import ExtractionOptions, IOCType, IOCTypeName
from iocparser.domain.type_filters import parse_ioc_types
from iocparser.errors import ValidationError
from iocparser.shared_utils import parse_bool_token, parse_string_filters

__all__ = [
    "ProcessingOptions",
    "get_bool_arg",
    "get_int_arg",
    "get_list_arg",
    "get_optional_str_arg",
    "get_str_arg",
    "int_arg_value",
    "int_value",
    "namespace_value",
    "parse_string_filters",
    "validated_int_arg",
]

INTEGER_VALUE_REQUIRED = "{field_name} requires an integer value"
INVALID_IOC_TYPE_FILTER = "Invalid IOC type for {flag}: {value}"
STRING_VALUE_REQUIRED = "{field_name} requires a string value"


def _require_str_value(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(STRING_VALUE_REQUIRED.format(field_name=field_name))
    return value


def validated_stix_types(value: object | None) -> str | None:
    """Validate a --stix-types value at the CLI boundary, returning it unchanged.

    The STIX renderer parses this string with parse_ioc_types, which raises a bare
    ValueError on an unknown type; left unguarded it surfaced as a generic
    "Unexpected error: <type>". Translate it to a ValidationError so the message
    matches --only/--exclude/--ioc-type instead of looking like a crash.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError(
            INVALID_IOC_TYPE_FILTER.format(flag="--stix-types", value=value)
        )
    try:
        parse_ioc_types(value)
    except ValueError as exc:
        raise ValidationError(
            INVALID_IOC_TYPE_FILTER.format(flag="--stix-types", value=exc)
        ) from exc
    return value


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
    if value is None:
        return default
    normalized = _require_str_value(value, field_name=name).strip()
    return normalized or default


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
    return default if value is None else int_arg_value(value, name)


def validated_int_arg(args: argparse.Namespace, name: str, default: int = 0) -> int:
    """Get an integer argument and raise ValidationError on bad input."""
    value: object = getattr(args, name, None)
    return default if value is None else int_arg_value(value, name)


def get_list_arg(args: argparse.Namespace, name: str) -> list[str]:
    """Get list argument from argparse namespace."""
    value: object = getattr(args, name, None)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        if not all(isinstance(item, str) for item in value):
            raise ValidationError(STRING_VALUE_REQUIRED.format(field_name=name))
        return [item for item in value if item.strip()]
    return [_require_str_value(value, field_name=name)]


def get_optional_str_arg(args: argparse.Namespace, name: str) -> str | None:
    """Get optional string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    if value is None:
        return None
    normalized = _require_str_value(value, field_name=name).strip()
    return normalized or None


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
            include_types=cls._parse_type_filter(get_optional_str_arg(args, "only"), flag="--only"),
            exclude_types=cls._parse_type_filter(
                get_optional_str_arg(args, "exclude"), flag="--exclude"
            ),
        )

    @staticmethod
    def _parse_type_filter(
        value: str | None, *, flag: str
    ) -> tuple[IOCType | IOCTypeName, ...]:
        # parse_ioc_types raises a bare ValueError on an unknown type; translate it to a
        # ValidationError so the CLI reports a clean message (like --severity) instead of
        # dumping a stack trace for what is just bad user input.
        try:
            return parse_ioc_types(value)
        except ValueError as exc:
            raise ValidationError(
                INVALID_IOC_TYPE_FILTER.format(flag=flag, value=exc)
            ) from exc

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
