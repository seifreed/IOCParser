from __future__ import annotations

from dataclasses import dataclass

from iocparser.domain.enums import IOCType, IOCTypeName


@dataclass(frozen=True)
class ExtractionOptions:
    """Shared extraction options used across application use cases."""

    file_type: str | None = None
    defang: bool = True
    check_warnings: bool = True
    force_update: bool = False
    include_types: tuple[IOCType | IOCTypeName, ...] = ()
    exclude_types: tuple[IOCType | IOCTypeName, ...] = ()

    def allows(self, ioc_type: IOCType | IOCTypeName) -> bool:
        """Return whether the IOC type should be included in the result."""
        if self.include_types and ioc_type not in self.include_types:
            return False
        return ioc_type not in self.exclude_types


@dataclass(frozen=True)
class PersistOptions:
    """Persistence options captured for a run."""

    defang: bool
    check_warnings: bool
    force_update: bool
    output_format: str

    def to_dict(self) -> dict[str, bool | str]:
        """Serialize options into a storage-friendly payload."""
        return {
            "defang": self.defang,
            "check_warnings": self.check_warnings,
            "force_update": self.force_update,
            "output_format": self.output_format,
        }
