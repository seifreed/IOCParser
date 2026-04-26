from __future__ import annotations

import argparse
from dataclasses import dataclass

from iocparser.domain.models import ExtractionOptions, IOCType, IOCTypeName
from iocparser.domain.type_filters import parse_ioc_types


def get_str_arg(args: argparse.Namespace, name: str, default: str = "") -> str:
    """Get string argument from argparse namespace."""
    value: object = getattr(args, name, None)
    return str(value) if value is not None else default


def get_bool_arg(args: argparse.Namespace, name: str) -> bool:
    """Get boolean argument from argparse namespace."""
    value: object = getattr(args, name, False)
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
