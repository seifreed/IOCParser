from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from iocparser.application.contracts import ExtractFileInput, ExtractTextInput, ExtractURLInput
from iocparser.application.use_cases import extract_from_file, extract_from_text, extract_from_url
from iocparser.client_extraction import build_extraction_options
from iocparser.domain.models import ExtractionOptions, ExtractionResult
from iocparser.errors import FileExistenceError, TypeValidationError
from iocparser.infrastructure.extraction import (
    DefaultIOCExtractionEngine,
    MagicTextSourceReader,
    RequestsURLDownloader,
    TemporaryFileCleaner,
)
from iocparser.interfaces.ports import WarningListService

_reader = MagicTextSourceReader()
_warning_service_holder: list[WarningListService] = []
_downloader = RequestsURLDownloader()
_extractor_engine = DefaultIOCExtractionEngine()
_temporary_resource_cleaner = TemporaryFileCleaner()

reader = _reader
downloader = _downloader
extractor_engine = _extractor_engine
temporary_resource_cleaner = _temporary_resource_cleaner


def _lazy_warning_service() -> WarningListService:
    if not _warning_service_holder:
        from iocparser.plugins import get_enricher

        _warning_service_holder.append(get_enricher("misp"))
    return _warning_service_holder[0]


def options(
    *,
    check_warnings: bool,
    force_update: bool,
    file_type: str | None = None,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> ExtractionOptions:
    return build_extraction_options(
        file_type=file_type,
        defang=defang,
        check_warnings=check_warnings,
        force_update=force_update,
        only=only,
        exclude=exclude,
    )


def current_warning_service(enabled: bool) -> WarningListService | None:
    return _lazy_warning_service() if enabled else None


def ensure_file_exists(file_path: str) -> None:
    if not Path(file_path).expanduser().is_file():
        raise FileExistenceError(str(file_path))


WarningServiceFactory = Callable[[bool], WarningListService | None]


def extract_file_result(
    file_path: str,
    *,
    check_warnings: bool,
    force_update: bool,
    file_type: str | None,
    defang: bool,
    only: str | None,
    exclude: str | None,
    current_warning_service: WarningServiceFactory,
) -> ExtractionResult:
    normalized_file_path = str(Path(file_path).expanduser())
    ensure_file_exists(normalized_file_path)
    return extract_from_file(
        ExtractFileInput(
            file_path=normalized_file_path,
            options=options(
                file_type=file_type,
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        ),
        extractor_engine=_extractor_engine,
        reader=_reader,
        warning_service=current_warning_service(check_warnings),
    )


def extract_text_result(
    text_content: str,
    *,
    check_warnings: bool,
    force_update: bool,
    defang: bool,
    only: str | None,
    exclude: str | None,
    current_warning_service: WarningServiceFactory,
) -> ExtractionResult:
    return extract_from_text(
        ExtractTextInput(
            text_content=text_content,
            options=options(
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        ),
        extractor_engine=_extractor_engine,
        warning_service=current_warning_service(check_warnings),
    )


def extract_url_result(
    url: str,
    *,
    check_warnings: bool,
    force_update: bool,
    defang: bool,
    only: str | None,
    exclude: str | None,
    current_warning_service: WarningServiceFactory,
) -> ExtractionResult:
    return extract_from_url(
        ExtractURLInput(
            url=url,
            options=options(
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        ),
        downloader=_downloader,
        reader=_reader,
        extractor_engine=_extractor_engine,
        temporary_resource_cleaner=_temporary_resource_cleaner,
        warning_service=current_warning_service(check_warnings),
    )


def grouped_payload(
    result: ExtractionResult,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    return result.grouped_iocs(), result.grouped_warnings()


def extract_result_from_file(
    file_path: str,
    check_warnings: bool = True,
    force_update: bool = False,
    file_type: str | None = None,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> ExtractionResult:
    return extract_file_result(
        file_path,
        check_warnings=check_warnings,
        force_update=force_update,
        file_type=file_type,
        defang=defang,
        only=only,
        exclude=exclude,
        current_warning_service=current_warning_service,
    )


def extract_iocs_from_file(
    file_path: str,
    check_warnings: bool = True,
    force_update: bool = False,
    file_type: str | None = None,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    return grouped_payload(
        extract_result_from_file(
            file_path,
            check_warnings=check_warnings,
            force_update=force_update,
            file_type=file_type,
            defang=defang,
            only=only,
            exclude=exclude,
        ),
    )


def extract_result_from_text(
    text_content: str,
    check_warnings: bool = True,
    force_update: bool = False,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> ExtractionResult:
    # Trust-boundary guard: a non-str here would otherwise crash deep in the
    # extractor engine (len(text_content)) with an opaque "NoneType has no len()".
    if not isinstance(text_content, str):
        raise TypeValidationError("text_content", "string", text_content)
    return extract_text_result(
        text_content,
        check_warnings=check_warnings,
        force_update=force_update,
        defang=defang,
        only=only,
        exclude=exclude,
        current_warning_service=current_warning_service,
    )


def extract_iocs_from_text(
    text_content: str,
    check_warnings: bool = True,
    force_update: bool = False,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    return grouped_payload(
        extract_result_from_text(
            text_content,
            check_warnings=check_warnings,
            force_update=force_update,
            defang=defang,
            only=only,
            exclude=exclude,
        ),
    )


def extract_result_from_url(
    url: str,
    check_warnings: bool = True,
    force_update: bool = False,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> ExtractionResult:
    return extract_url_result(
        url,
        check_warnings=check_warnings,
        force_update=force_update,
        defang=defang,
        only=only,
        exclude=exclude,
        current_warning_service=current_warning_service,
    )


def extract_iocs_from_url(
    url: str,
    check_warnings: bool = True,
    force_update: bool = False,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> tuple[dict[str, list[str | dict[str, str]]], dict[str, list[dict[str, str]]]]:
    return grouped_payload(
        extract_result_from_url(
            url,
            check_warnings=check_warnings,
            force_update=force_update,
            defang=defang,
            only=only,
            exclude=exclude,
        ),
    )


__all__ = [
    "extract_iocs_from_file",
    "extract_iocs_from_text",
    "extract_iocs_from_url",
    "extract_result_from_file",
    "extract_result_from_text",
    "extract_result_from_url",
]
