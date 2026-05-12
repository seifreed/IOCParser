from __future__ import annotations

from dataclasses import dataclass, field

from iocparser.application.contracts import ExtractTextInput
from iocparser.application.use_cases import extract_from_text
from iocparser.domain.models import ExtractionOptions, ExtractionResult
from iocparser.infrastructure.extraction import (
    DefaultIOCExtractionEngine,
    MagicTextSourceReader,
    RequestsURLDownloader,
    TemporaryFileCleaner,
)
from iocparser.infrastructure.warninglists_service import CompositeWarningListService
from iocparser.interfaces.ports import (
    IOCExtractionEngine,
    TemporaryResourceCleaner,
    TextSourceReader,
    URLDownloader,
    WarningListService,
)
from iocparser.plugins import get_enricher, get_extractor, get_postprocessor


@dataclass(frozen=True)
class ClientPluginSettings:
    enrichers: tuple[str, ...]
    extractors: tuple[str, ...]
    postprocessors: tuple[str, ...]


@dataclass(frozen=True)
class ClientExtractionAdapters:
    reader: TextSourceReader
    extractor_engine: IOCExtractionEngine
    downloader: URLDownloader | None = None
    temporary_resource_cleaner: TemporaryResourceCleaner | None = None


@dataclass(frozen=True)
class ClientExtractionRequest:
    check_warnings: bool = True
    force_update: bool = False
    defang: bool = True
    only: str | None = None
    exclude: str | None = None
    file_type: str | None = None


def build_extraction_options(
    *,
    check_warnings: bool,
    force_update: bool,
    file_type: str | None = None,
    defang: bool = True,
    only: str | None = None,
    exclude: str | None = None,
) -> ExtractionOptions:
    from iocparser.domain.type_filters import parse_ioc_types

    return ExtractionOptions(
        file_type=file_type,
        defang=defang,
        check_warnings=check_warnings,
        force_update=force_update,
        include_types=parse_ioc_types(only),
        exclude_types=parse_ioc_types(exclude),
    )


def merge_extraction_results(base: ExtractionResult, extra: ExtractionResult) -> ExtractionResult:
    from iocparser.domain.models import ioc_type_name

    ioc_map = {(ioc_type_name(ioc.ioc_type), ioc.value.raw): ioc for ioc in base.iocs}
    warning_map = {
        (
            ioc_type_name(warning.ioc.ioc_type),
            warning.ioc.value.raw,
            warning.warning_list,
            warning.description,
        ): warning
        for warning in base.warnings
    }
    for ioc in extra.iocs:
        ioc_map.setdefault((ioc_type_name(ioc.ioc_type), ioc.value.raw), ioc)
    for warning in extra.warnings:
        warning_map.setdefault(
            (
                ioc_type_name(warning.ioc.ioc_type),
                warning.ioc.value.raw,
                warning.warning_list,
                warning.description,
            ),
            warning,
        )
    return ExtractionResult(iocs=tuple(ioc_map.values()), warnings=tuple(warning_map.values()))


def plugin_settings(
    *,
    enrichers: tuple[str, ...],
    extractors: tuple[str, ...],
    postprocessors: tuple[str, ...],
) -> ClientPluginSettings:
    return ClientPluginSettings(
        enrichers=enrichers,
        extractors=extractors,
        postprocessors=postprocessors,
    )


def extraction_adapters(
    *,
    reader: TextSourceReader,
    extractor_engine: IOCExtractionEngine,
    downloader: URLDownloader,
    temporary_resource_cleaner: TemporaryResourceCleaner,
) -> ClientExtractionAdapters:
    return ClientExtractionAdapters(
        reader=reader,
        extractor_engine=extractor_engine,
        downloader=downloader,
        temporary_resource_cleaner=temporary_resource_cleaner,
    )


def extraction_request(
    *,
    check_warnings: bool,
    force_update: bool,
    defang: bool,
    only: str | None,
    exclude: str | None,
    file_type: str | None = None,
) -> ClientExtractionRequest:
    return ClientExtractionRequest(
        check_warnings=check_warnings,
        force_update=force_update,
        defang=defang,
        only=only,
        exclude=exclude,
        file_type=file_type,
    )


def extract_text_result(
    *,
    text_content: str,
    extractor_engine: IOCExtractionEngine,
    plugins: ClientPluginSettings,
    request: ClientExtractionRequest,
) -> ExtractionResult:
    options = build_extraction_options(
        check_warnings=request.check_warnings,
        force_update=request.force_update,
        defang=request.defang,
        only=request.only,
        exclude=request.exclude,
    )
    base_result = extract_from_text(
        ExtractTextInput(text_content=text_content, options=options),
        extractor_engine=extractor_engine,
        warning_service=warning_service_for(
            enabled=request.check_warnings, enrichers=plugins.enrichers
        ),
    )
    return apply_plugins(
        text_content=text_content,
        options=options,
        result=base_result,
        extractors=plugins.extractors,
        postprocessors=plugins.postprocessors,
    )


def extract_file_result(
    *,
    file_path: str,
    adapters: ClientExtractionAdapters,
    plugins: ClientPluginSettings,
    request: ClientExtractionRequest,
) -> ExtractionResult:
    options = build_extraction_options(
        file_type=request.file_type,
        check_warnings=request.check_warnings,
        force_update=request.force_update,
        defang=request.defang,
        only=request.only,
        exclude=request.exclude,
    )
    text_content = adapters.reader.read(file_path, options)
    result = extract_from_text(
        ExtractTextInput(text_content=text_content, options=options),
        extractor_engine=adapters.extractor_engine,
        warning_service=warning_service_for(
            enabled=options.check_warnings, enrichers=plugins.enrichers
        ),
    )
    return apply_plugins(
        text_content=text_content,
        options=options,
        result=result,
        extractors=plugins.extractors,
        postprocessors=plugins.postprocessors,
    )


def _missing_url_adapters_error() -> ValueError:
    return ValueError("Missing URL adapters")


def extract_url_result(
    *,
    url: str,
    adapters: ClientExtractionAdapters,
    plugins: ClientPluginSettings,
    request: ClientExtractionRequest,
) -> ExtractionResult:
    if adapters.downloader is None or adapters.temporary_resource_cleaner is None:
        raise _missing_url_adapters_error()
    temp_file = adapters.downloader.download(url)
    try:
        return extract_file_result(
            file_path=temp_file,
            adapters=adapters,
            plugins=plugins,
            request=request,
        )
    finally:
        adapters.temporary_resource_cleaner.cleanup(temp_file)


def warning_service_for(*, enabled: bool, enrichers: tuple[str, ...]) -> WarningListService | None:
    if not enabled or not enrichers:
        return None
    services = tuple(get_enricher(name) for name in enrichers)
    return services[0] if len(services) == 1 else CompositeWarningListService(services)


def apply_plugins(
    *,
    text_content: str,
    options: ExtractionOptions,
    result: ExtractionResult,
    extractors: tuple[str, ...],
    postprocessors: tuple[str, ...],
) -> ExtractionResult:
    merged = result
    for name in extractors:
        merged = merge_extraction_results(
            merged, get_extractor(name).extract(text_content, defang=options.defang)
        )
    for name in postprocessors:
        merged = get_postprocessor(name).process(merged)
    return merged.filter_types(options.include_types, options.exclude_types)


@dataclass
class IOCParserClient:
    """Reusable extraction client with shared adapters and plugin pipeline."""

    reader: TextSourceReader = field(default_factory=MagicTextSourceReader)
    downloader: URLDownloader = field(default_factory=RequestsURLDownloader)
    extractor_engine: IOCExtractionEngine = field(default_factory=DefaultIOCExtractionEngine)
    temporary_resource_cleaner: TemporaryResourceCleaner = field(
        default_factory=TemporaryFileCleaner
    )
    enrichers: tuple[str, ...] = ("misp",)
    extractors: tuple[str, ...] = ()
    postprocessors: tuple[str, ...] = ()

    def _plugins(self) -> ClientPluginSettings:
        return plugin_settings(
            enrichers=self.enrichers,
            extractors=self.extractors,
            postprocessors=self.postprocessors,
        )

    def _adapters(self) -> ClientExtractionAdapters:
        return extraction_adapters(
            reader=self.reader,
            extractor_engine=self.extractor_engine,
            downloader=self.downloader,
            temporary_resource_cleaner=self.temporary_resource_cleaner,
        )

    def _request(
        self,
        *,
        check_warnings: bool,
        force_update: bool,
        defang: bool,
        only: str | None,
        exclude: str | None,
        file_type: str | None = None,
    ) -> ClientExtractionRequest:
        return extraction_request(
            check_warnings=check_warnings,
            force_update=force_update,
            defang=defang,
            only=only,
            exclude=exclude,
            file_type=file_type,
        )

    def _warning_service(self, enabled: bool) -> WarningListService | None:
        return warning_service_for(enabled=enabled, enrichers=self.enrichers)

    def _apply_plugins(
        self, text_content: str, options: ExtractionOptions, result: ExtractionResult
    ) -> ExtractionResult:
        return apply_plugins(
            text_content=text_content,
            options=options,
            result=result,
            extractors=self.extractors,
            postprocessors=self.postprocessors,
        )

    def extract_result_from_text(
        self,
        text_content: str,
        *,
        check_warnings: bool = True,
        force_update: bool = False,
        defang: bool = True,
        only: str | None = None,
        exclude: str | None = None,
    ) -> ExtractionResult:
        return extract_text_result(
            text_content=text_content,
            extractor_engine=self.extractor_engine,
            plugins=self._plugins(),
            request=self._request(
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        )

    def extract_result_from_file(
        self,
        file_path: str,
        *,
        file_type: str | None = None,
        check_warnings: bool = True,
        force_update: bool = False,
        defang: bool = True,
        only: str | None = None,
        exclude: str | None = None,
    ) -> ExtractionResult:
        return extract_file_result(
            file_path=file_path,
            adapters=self._adapters(),
            plugins=self._plugins(),
            request=self._request(
                file_type=file_type,
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        )

    def extract_result_from_url(
        self,
        url: str,
        *,
        check_warnings: bool = True,
        force_update: bool = False,
        defang: bool = True,
        only: str | None = None,
        exclude: str | None = None,
    ) -> ExtractionResult:
        return extract_url_result(
            url=url,
            adapters=self._adapters(),
            plugins=self._plugins(),
            request=self._request(
                check_warnings=check_warnings,
                force_update=force_update,
                defang=defang,
                only=only,
                exclude=exclude,
            ),
        )


__all__ = [
    "ClientExtractionAdapters",
    "ClientExtractionRequest",
    "ClientPluginSettings",
    "IOCParserClient",
    "apply_plugins",
    "build_extraction_options",
    "extract_file_result",
    "extract_text_result",
    "extract_url_result",
    "extraction_adapters",
    "extraction_request",
    "merge_extraction_results",
    "plugin_settings",
    "warning_service_for",
]
