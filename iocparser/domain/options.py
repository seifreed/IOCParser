from __future__ import annotations

from dataclasses import dataclass

from iocparser.domain.enums import IOCType, IOCTypeName, get_custom_ioc_type, ioc_type_name


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
        name = ioc_type_name(ioc_type)
        custom_type = get_custom_ioc_type(ioc_type)
        base_name = ioc_type_name(custom_type.base_type) if custom_type is not None else name
        include_names = {ioc_type_name(item) for item in self.include_types}
        exclude_names = {ioc_type_name(item) for item in self.exclude_types}
        if include_names and name not in include_names and base_name not in include_names:
            return False
        return name not in exclude_names and base_name not in exclude_names


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
