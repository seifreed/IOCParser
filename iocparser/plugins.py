from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
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
from iocparser.errors import ValidationError
from iocparser.infrastructure.warninglists_service import MISPWarningListService
from iocparser.interfaces.ports import OutputRenderer, WarningListService

_logger = logging.getLogger(__name__)
UNKNOWN_PLUGIN_ERROR = "Unknown {kind} '{name}'. Available: {available}"


def _resolve_plugin[FactoryT](registry: dict[str, FactoryT], name: str, *, kind: str) -> FactoryT:
    """Look a plugin up by name, raising a clean error (not a bare KeyError) if absent."""
    normalized = name.strip()
    try:
        return registry[normalized.lower()]
    except KeyError as exc:
        available = ", ".join(sorted(registry)) or "(none)"
        raise ValidationError(
            UNKNOWN_PLUGIN_ERROR.format(kind=kind, name=name, available=available)
        ) from exc
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
_load_lock = threading.Lock()


class ExtractorPlugin(Protocol):
    """Plugin contract for extra text extraction passes."""

    def extract(self, text_content: str, *, defang: bool = True) -> ExtractionResult:
        """Extract additional indicators from text."""


class ResultPostProcessor(Protocol):
    """Plugin contract for post-processing extraction results."""

    def process(self, result: ExtractionResult) -> ExtractionResult:
        """Return a transformed extraction result."""


def _warn_on_builtin_override(
    name: str, builtin_names: set[str], registry: Mapping[str, object], *, kind: str
) -> None:
    """Warn when a registration replaces an already-registered built-in plugin.

    Overriding a built-in is allowed, but it should be visible however it happens —
    the entry-point loader used to warn while a direct register_*() call clobbered a
    built-in (e.g. "json", "text", "misp") silently. ``name in registry`` is what makes
    this an override, so the initial built-in registration (registry still empty for the
    name) does not warn.
    """
    key = name.lower()
    if key in builtin_names and key in registry:
        _logger.warning("Plugin %s '%s' overrides built-in %s", kind, name, kind)


def register_renderer(name: str, factory: RendererFactory) -> None:
    """Register an output renderer plugin."""
    _warn_on_builtin_override(name, _BUILTIN_RENDERER_NAMES, _renderer_registry, kind="renderer")
    _renderer_registry[name.lower()] = factory


def get_renderer(
    name: str, *, with_context: bool = False, stix_types: str | None = None
) -> OutputRenderer:
    """Resolve a renderer by name."""
    _load_entry_point_plugins()
    return _resolve_plugin(_renderer_registry, name, kind="renderer")(with_context, stix_types)


def require_renderer(name: str) -> None:
    """Validate a renderer name at the CLI boundary without constructing it.

    Lets an unknown --renderer fail fast (before any extraction/download work) with the
    same error the late get_renderer() call would raise, matching --enricher/--extractor.
    """
    _load_entry_point_plugins()
    _resolve_plugin(_renderer_registry, name, kind="renderer")


def renderer_names() -> tuple[str, ...]:
    """List registered renderer names."""
    _load_entry_point_plugins()
    return tuple(sorted(_renderer_registry))


def register_enricher(name: str, factory: EnricherFactory) -> None:
    """Register an enrichment service plugin."""
    _warn_on_builtin_override(name, _BUILTIN_ENRICHER_NAMES, _enricher_registry, kind="enricher")
    _enricher_registry[name.lower()] = factory


def get_enricher(name: str = "misp") -> WarningListService:
    """Resolve an enrichment service by name."""
    _load_entry_point_plugins()
    return _resolve_plugin(_enricher_registry, name, kind="enricher")()


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
    return _resolve_plugin(_extractor_registry, name, kind="extractor")()


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
    return _resolve_plugin(_postprocessor_registry, name, kind="postprocessor")()


def postprocessor_names() -> tuple[str, ...]:
    """List registered post-processor plugin names."""
    _load_entry_point_plugins()
    return tuple(sorted(_postprocessor_registry))


def register_ioc_type_plugin(name: str, factory: IOCTypePluginFactory) -> None:
    """Register a plugin that contributes a custom IOC type."""
    plugin_name = name.lower()
    _ioc_type_registry[plugin_name] = factory
    if _plugin_state["entry_points_loaded"]:
        _register_ioc_type_plugin(plugin_name)


def _ioc_type_plugin_definition(name: str) -> dict[str, object]:
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
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"Expected string values, got {type(item).__name__}")
        items.append(item)
    return tuple(items)


def _require_str_field(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"Expected {field} to be string, got {type(value).__name__}")
    return value


def _load_group[FactoryT](
    discovered: EntryPoints,
    *,
    group: str,
    kind: str,
    register: Callable[[str, FactoryT], None],
) -> None:
    # register_*() warns when an entry point overrides a built-in, so no check here.
    for entry_point in discovered.select(group=group):
        try:
            # A third-party plugin whose load() raises (bad import, missing
            # dependency) must not abort discovery of the remaining (including
            # built-in) plugins, so the failure is logged and the plugin skipped.
            register(entry_point.name, cast("FactoryT", entry_point.load()))
        except Exception as exc:
            _logger.warning(
                "Skipping %s plugin '%s' that failed to load: %s", kind, entry_point.name, exc
            )


def _load_discovered_entry_points(discovered: EntryPoints) -> None:
    _load_group(
        discovered,
        group="iocparser.renderers",
        kind="renderer",
        register=register_renderer,
    )
    _load_group(
        discovered,
        group="iocparser.enrichers",
        kind="enricher",
        register=register_enricher,
    )
    _load_group(
        discovered, group="iocparser.extractors", kind="extractor", register=register_extractor
    )
    _load_group(
        discovered,
        group="iocparser.postprocessors",
        kind="postprocessor",
        register=register_postprocessor,
    )
    _load_group(
        discovered,
        group="iocparser.ioc_types",
        kind="ioc_type",
        register=register_ioc_type_plugin,
    )


def _register_ioc_type_plugin(plugin_name: str) -> None:
    try:
        definition = _ioc_type_plugin_definition(plugin_name)
        base_type_raw = _require_str_field(definition.get("base_type", "urls"), field="base_type").strip()
        if not base_type_raw:
            _logger.warning("Plugin '%s' has empty base_type, skipping", plugin_name)
            return
        name = _require_str_field(definition.get("name", plugin_name), field="name")
        severity = definition.get("severity")
        if severity is not None:
            severity = _require_str_field(severity, field="severity")
        stix_pattern = definition.get("stix_pattern")
        if stix_pattern is not None:
            stix_pattern = _require_str_field(stix_pattern, field="stix_pattern")
        register_custom_ioc_type(
            name,
            base_type=base_type_raw,
            aliases=_string_tuple(definition.get("aliases")),
            severity=severity,
            tags=_string_tuple(definition.get("tags")),
            stix_pattern=stix_pattern,
        )
    except (ValueError, TypeError, KeyError) as exc:
        _logger.warning("Failed to register IOC type plugin '%s': %s", plugin_name, exc)


def _register_discovered_ioc_types() -> None:
    for plugin_name in tuple(sorted(_ioc_type_registry)):
        _register_ioc_type_plugin(plugin_name)


def _load_entry_point_plugins() -> None:
    # Resolvers call this lazily; under concurrent first use an unlocked check-then-act
    # let every thread run the full entry-point discovery + re-register, re-firing
    # override warnings. Double-checked locking loads exactly once.
    if _plugin_state["entry_points_loaded"]:
        return
    with _load_lock:
        if not _plugin_state["entry_points_loaded"]:
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
