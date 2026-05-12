from __future__ import annotations

from iocparser.domain.models import (
    ExtractionResult,
    PersistedRunDiff,
    PersistedRunExport,
    ioc_type_name,
)


def diff_run_exports(
    left: PersistedRunExport,
    right: PersistedRunExport,
    *,
    left_run_id: int,
    right_run_id: int,
) -> PersistedRunDiff:
    left_ioc_keys = {
        (ioc_type_name(ioc.ioc_type), ioc.canonical_value()): ioc for ioc in left.result.iocs
    }
    right_ioc_keys = {
        (ioc_type_name(ioc.ioc_type), ioc.canonical_value()): ioc for ioc in right.result.iocs
    }
    left_warning_keys = {
        (
            ioc_type_name(warning.ioc.ioc_type),
            warning.ioc.canonical_value(),
            warning.warning_list,
            warning.description,
        ): warning
        for warning in left.result.warnings
    }
    right_warning_keys = {
        (
            ioc_type_name(warning.ioc.ioc_type),
            warning.ioc.canonical_value(),
            warning.warning_list,
            warning.description,
        ): warning
        for warning in right.result.warnings
    }
    return PersistedRunDiff(
        left_run_id=left_run_id,
        right_run_id=right_run_id,
        added=ExtractionResult(
            iocs=tuple(ioc for key, ioc in right_ioc_keys.items() if key not in left_ioc_keys),
            warnings=tuple(
                warning
                for key, warning in right_warning_keys.items()
                if key not in left_warning_keys
            ),
        ),
        removed=ExtractionResult(
            iocs=tuple(ioc for key, ioc in left_ioc_keys.items() if key not in right_ioc_keys),
            warnings=tuple(
                warning
                for key, warning in left_warning_keys.items()
                if key not in right_warning_keys
            ),
        ),
    )
