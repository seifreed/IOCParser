from __future__ import annotations

import logging
from collections.abc import Callable
from importlib.metadata import EntryPoints, entry_points
from typing import Protocol, cast

from iocparser.adapters.renderers import (
    CSVOutputRenderer,
    JSONLinesOutputRenderer,
    JSONOutputRenderer,
    STIXOutputRenderer,
    TextOutputRenderer,
)
from iocparser.domain.models import (
    ExtractionResult,
    custom_ioc_type_names,
    register_custom_ioc_type,
)
from iocparser.domain.type_filters import parse_ioc_types
from iocparser.infrastructure.warninglists_service import MISPWarningListService
from iocparser.interfaces.ports import OutputRenderer, WarningListService

_logger = logging.getLogger(__name__)
_BUILTIN_RENDERER_NAMES: set[str] = set()
_BUILTIN_ENRICHER_NAMES: set[str] = set()

RendererFactory = Callable[[bool, str | None], OutputRenderer]
EnricherFactory = Callable[[], WarningListService]
PostProcessorFactory = Callable[[], "ResultPostProcessor"]
ExtractorFactory = Callable[[], "ExtractorPlugin"]
IOCTypePluginFactory = Callable[[], dict[str, object]]

_renderer_registry: dict[str, RendererFactory] = {}
_enricher_registry: dict[str, EnricherFactory] = {}
_postprocessor_registry: dict[str, PostProcessorFactory] = {}
_extractor_registry: dict[str, ExtractorFactory] = {}
_ioc_type_registry: dict[str, IOCTypePluginFactory] = {}
_plugin_state = {"entry_points_loaded": False}


class ExtractorPlugin(Protocol):
    """Plugin contract for extra text extraction passes."""

    def extract(self, text_content: str, *, defang: bool = True) -> ExtractionResult:
        """Extract additional indicators from text."""


class ResultPostProcessor(Protocol):
    """Plugin contract for post-processing extraction results."""

    def process(self, result: ExtractionResult) -> ExtractionResult:
        """Return a transformed extraction result."""


def register_renderer(name: str, factory: RendererFactory) -> None:
    """Register an output renderer plugin."""
    _renderer_registry[name.lower()] = factory


def get_renderer(
    name: str, *, with_context: bool = False, stix_types: str | None = None
) -> OutputRenderer:
    """Resolve a renderer by name."""
    _load_entry_point_plugins()
    return _renderer_registry[name.lower()](with_context, stix_types)


def renderer_names() -> tuple[str, ...]:
    """List registered renderer names."""
    _load_entry_point_plugins()
    return tuple(sorted(_renderer_registry))


def register_enricher(name: str, factory: EnricherFactory) -> None:
    """Register an enrichment service plugin."""
    _enricher_registry[name.lower()] = factory


def get_enricher(name: str = "misp") -> WarningListService:
    """Resolve an enrichment service by name."""
    _load_entry_point_plugins()
    return _enricher_registry[name.lower()]()


def enricher_names() -> tuple[str, ...]:
    """List registered enricher names."""
    _load_entry_point_plugins()
    return tuple(sorted(_enricher_registry))


def register_extractor(name: str, factory: ExtractorFactory) -> None:
    """Register an extractor plugin."""
    _extractor_registry[name.lower()] = factory


def get_extractor(name: str) -> ExtractorPlugin:
    """Resolve an extractor plugin by name."""
    _load_entry_point_plugins()
    return _extractor_registry[name.lower()]()


def extractor_names() -> tuple[str, ...]:
    """List registered extractor plugin names."""
    _load_entry_point_plugins()
    return tuple(sorted(_extractor_registry))


def register_postprocessor(name: str, factory: PostProcessorFactory) -> None:
    """Register a result post-processor plugin."""
    _postprocessor_registry[name.lower()] = factory


def get_postprocessor(name: str) -> ResultPostProcessor:
    """Resolve a result post-processor by name."""
    _load_entry_point_plugins()
    return _postprocessor_registry[name.lower()]()


def postprocessor_names() -> tuple[str, ...]:
    """List registered post-processor plugin names."""
    _load_entry_point_plugins()
    return tuple(sorted(_postprocessor_registry))


def register_ioc_type_plugin(name: str, factory: IOCTypePluginFactory) -> None:
    """Register a plugin that contributes a custom IOC type."""
    _ioc_type_registry[name.lower()] = factory


def get_ioc_type_plugin(name: str) -> dict[str, object]:
    """Resolve a custom IOC type plugin definition."""
    return dict(_ioc_type_registry[name.lower()]())


def ioc_type_plugin_names() -> tuple[str, ...]:
    """List registered IOC type plugin names."""
    _load_entry_point_plugins()
    return tuple(sorted(_ioc_type_registry))


def custom_ioc_types() -> tuple[str, ...]:
    """List registered custom IOC types."""
    _load_entry_point_plugins()
    return custom_ioc_type_names()


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value)


def _load_discovered_entry_points(discovered: EntryPoints) -> None:
    for entry_point in discovered.select(group="iocparser.renderers"):
        name_lower = entry_point.name.lower()
        if name_lower in _BUILTIN_RENDERER_NAMES:
            _logger.warning("Plugin renderer '%s' overrides built-in renderer", name_lower)
        register_renderer(entry_point.name, cast("RendererFactory", entry_point.load()))
    for entry_point in discovered.select(group="iocparser.enrichers"):
        name_lower = entry_point.name.lower()
        if name_lower in _BUILTIN_ENRICHER_NAMES:
            _logger.warning("Plugin enricher '%s' overrides built-in enricher", name_lower)
        register_enricher(entry_point.name, cast("EnricherFactory", entry_point.load()))
    for entry_point in discovered.select(group="iocparser.extractors"):
        register_extractor(entry_point.name, cast("ExtractorFactory", entry_point.load()))
    for entry_point in discovered.select(group="iocparser.postprocessors"):
        register_postprocessor(entry_point.name, cast("PostProcessorFactory", entry_point.load()))
    for entry_point in discovered.select(group="iocparser.ioc_types"):
        register_ioc_type_plugin(entry_point.name, cast("IOCTypePluginFactory", entry_point.load()))


def _register_discovered_ioc_types() -> None:
    for plugin_name in tuple(sorted(_ioc_type_registry)):
        try:
            definition = get_ioc_type_plugin(plugin_name)
            base_type_raw = str(definition.get("base_type", "urls")).strip()
            if not base_type_raw:
                _logger.warning("Plugin '%s' has empty base_type, skipping", plugin_name)
                continue
            register_custom_ioc_type(
                str(definition.get("name", plugin_name)),
                base_type=base_type_raw,
                aliases=_string_tuple(definition.get("aliases")),
                severity=str(definition["severity"])
                if definition.get("severity") is not None
                else None,
                tags=_string_tuple(definition.get("tags")),
                stix_pattern=str(definition["stix_pattern"])
                if definition.get("stix_pattern") is not None
                else None,
            )
        except (ValueError, TypeError, KeyError) as exc:
            _logger.warning("Failed to register IOC type plugin '%s': %s", plugin_name, exc)


def _load_entry_point_plugins() -> None:
    if _plugin_state["entry_points_loaded"]:
        return
    _load_discovered_entry_points(entry_points())
    _register_discovered_ioc_types()
    _plugin_state["entry_points_loaded"] = True


def _register_builtin_plugins() -> None:
    for name in ("text", "json", "jsonl", "csv", "stix"):
        _BUILTIN_RENDERER_NAMES.add(name)
    _BUILTIN_ENRICHER_NAMES.add("misp")
    register_renderer(
        "text", lambda with_context, _stix: TextOutputRenderer(include_context=with_context)
    )
    register_renderer(
        "json", lambda with_context, _stix: JSONOutputRenderer(include_context=with_context)
    )
    register_renderer("jsonl", lambda _with_context, _stix: JSONLinesOutputRenderer())
    register_renderer("csv", lambda _with_context, _stix: CSVOutputRenderer())
    register_renderer(
        "stix",
        lambda _with_context, stix_types: STIXOutputRenderer(
            allowed_types=set(parse_ioc_types(stix_types)) or None,
        ),
    )
    register_enricher("misp", MISPWarningListService)


_register_builtin_plugins()
