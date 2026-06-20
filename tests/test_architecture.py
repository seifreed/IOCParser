from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IOCPARSER_ROOT = REPO_ROOT / "iocparser"
NEW_LAYER_DIRS = (
    IOCPARSER_ROOT / "domain",
    IOCPARSER_ROOT / "application",
    IOCPARSER_ROOT / "interfaces",
    IOCPARSER_ROOT / "adapters",
    IOCPARSER_ROOT / "infrastructure",
)


def _imports_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _call_names_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                calls.add(f"{node.func.value.id}.{node.func.attr}")
    return calls


def _top_level_nodes(path: Path) -> list[ast.stmt]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return tree.body


def _decision_points_for(path: Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    decision_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.BoolOp,
        ast.IfExp,
        ast.comprehension,
    )
    return sum(1 for node in ast.walk(tree) if isinstance(node, decision_nodes))


def test_domain_does_not_depend_on_application_or_infrastructure() -> None:
    domain_dir = IOCPARSER_ROOT / "domain"
    forbidden = (
        "iocparser.application",
        "iocparser.infrastructure",
        "iocparser.adapters",
        "iocparser.cli",
    )
    for path in domain_dir.glob("*.py"):
        imports = _imports_for(path)
        assert not any(
            imported.startswith(prefix) for imported in imports for prefix in forbidden
        ), f"{path.name} imports forbidden outer-layer modules: {sorted(imports)}"


def test_application_depends_on_ports_not_infrastructure() -> None:
    application_dir = IOCPARSER_ROOT / "application"
    forbidden = ("iocparser.infrastructure", "iocparser.adapters", "iocparser.cli")
    for path in application_dir.glob("*.py"):
        imports = _imports_for(path)
        assert not any(
            imported.startswith(prefix) for imported in imports for prefix in forbidden
        ), f"{path.name} imports forbidden infrastructure modules: {sorted(imports)}"


def test_new_layers_do_not_import_removed_modules_package() -> None:
    forbidden = (
        "iocparser.core",
        "iocparser.extraction",
        "iocparser.download",
        "iocparser.main",
    )
    for layer_dir in NEW_LAYER_DIRS:
        for path in layer_dir.glob("*.py"):
            imports = _imports_for(path)
            assert not any(
                imported.startswith(prefix) for imported in imports for prefix in forbidden
            ), f"{path.name} imports removed modules package entries: {sorted(imports)}"


def test_domain_and_application_modules_stay_small_enough_to_review() -> None:
    limits = {
        # 350 -> 355 for register_custom_ioc_type's severity validation: a custom type
        # registered with an unrecognized severity (e.g. "critical") is now rejected
        # instead of being stored and silently dropped by min_severity filtering.
        IOCPARSER_ROOT / "domain": 355,
        # 270 -> 272 for the benign-redelivery guard in distributed_use_cases.py: a
        # transient mark_completed/mark_failed/requeue failure now marks the job handled
        # so the message redelivers instead of dead-lettering succeeded/retryable work.
        IOCPARSER_ROOT / "application": 272,
        IOCPARSER_ROOT / "adapters": 300,
    }
    for directory, limit in limits.items():
        for path in directory.glob("*.py"):
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            assert line_count <= limit, f"{path.name} is too large ({line_count} lines > {limit})"


def test_grouped_infrastructure_subpackages_stay_small_enough_to_review() -> None:
    limits = {
        IOCPARSER_ROOT / "infrastructure" / "extraction": 60,
        IOCPARSER_ROOT / "infrastructure" / "persistence": 40,
        # 1250 -> 1256 for the per-dialect literal origin-id SQL that replaced an
        # f-string interpolation (bandit B608 hardening, no #nosec).
        # 1256 -> 1267 for dialect-aware compact_history (SQLite VACUUM vs MySQL/MariaDB
        # OPTIMIZE TABLE); VACUUM is a syntax error on MariaDB.
        IOCPARSER_ROOT / "infrastructure" / "persistence" / "history": 1267,
        # 700 -> 713 for _date_to_clauses: a date-only --date-to is now inclusive of the
        # whole day (compare `< next day`) instead of excluding same-day runs at midnight.
        IOCPARSER_ROOT / "infrastructure" / "persistence" / "query": 713,
        IOCPARSER_ROOT / "infrastructure" / "queueing": 30,
        IOCPARSER_ROOT / "infrastructure" / "runtime": 45,
        IOCPARSER_ROOT / "infrastructure" / "migration_revisions": 80,
    }
    for directory, limit in limits.items():
        globber = (
            directory.glob
            if directory == IOCPARSER_ROOT / "infrastructure" / "persistence"
            else directory.rglob
        )
        for path in globber("*.py"):
            line_count = len(path.read_text(encoding="utf-8").splitlines())
            assert line_count <= limit, (
                f"{path.relative_to(REPO_ROOT)} is too large ({line_count} lines > {limit})"
            )


def test_public_facades_stay_thin() -> None:
    facade_limits = {
        IOCPARSER_ROOT / "__init__.py": 180,
        IOCPARSER_ROOT / "api_pipeline.py": 80,
        IOCPARSER_ROOT / "api_persistence.py": 90,
        IOCPARSER_ROOT / "cli.py": 240,
        IOCPARSER_ROOT / "cli_args.py": 60,
        IOCPARSER_ROOT / "cli_dispatch.py": 150,
        # Raised from 340 for boundary input validation (reject negative limit/offset
        # and --keep-latest, validate --severity on export/diff like search) so the CLI
        # matches the programmatic API instead of silently clamping/passing bad input.
        # Raised to 365 to translate the query layer's "run not found" ValueError into a
        # clean ValidationError at the CLI boundary (export-run/diff-runs/diff-latest)
        # instead of surfacing it as an unexpected-error stack trace.
        IOCPARSER_ROOT / "cli_queries.py": 365,
        IOCPARSER_ROOT / "cli_processing.py": 80,
        IOCPARSER_ROOT / "cli_processing_urls.py": 560,
        IOCPARSER_ROOT / "cli_processing_single.py": 120,
        IOCPARSER_ROOT / "cli_persistence.py": 280,
        IOCPARSER_ROOT / "client.py": 40,
        IOCPARSER_ROOT / "cli_runtime.py": 180,
        IOCPARSER_ROOT / "distributed_pipeline.py": 145,
        # Raised from 145 for graceful-shutdown stop_event propagation into the
        # per-cycle run loop (prompt break on stop instead of draining the batch).
        IOCPARSER_ROOT / "worker_service.py": 152,
        IOCPARSER_ROOT / "cli_schema.py": 220,
        IOCPARSER_ROOT / "domain" / "models.py": 60,
        IOCPARSER_ROOT / "infrastructure" / "warninglists.py": 180,
    }
    for path, limit in facade_limits.items():
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count <= limit, (
            f"{path.name} stopped being a thin facade ({line_count} lines > {limit})"
        )


def test_domain_models_facade_only_reexports_domain_symbols() -> None:
    path = IOCPARSER_ROOT / "domain" / "models.py"
    imports = _imports_for(path)
    assert imports
    allowed_prefixes = ("__future__", "iocparser.domain.")
    assert all(imported.startswith(allowed_prefixes) for imported in imports)

    for node in _top_level_nodes(path):
        assert not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)), (
            "domain/models.py must stay a pure re-export facade"
        )


def test_public_root_facade_only_reexports_public_api_and_boundary_symbols() -> None:
    path = IOCPARSER_ROOT / "__init__.py"
    imports = _imports_for(path)
    allowed_prefixes = (
        "__future__",
        # __version__ is sourced from this tiny internal helper (single source of truth:
        # the installed distribution metadata) so it can't drift from pyproject.
        "iocparser._version",
        "iocparser.api_",
        "iocparser.cli",
        "iocparser.client",
        "iocparser.distributed_pipeline",
        "iocparser.domain.models",
        "iocparser.domain.pipeline",
        "iocparser.infrastructure.extraction",
        "iocparser.infrastructure.queueing",
        "iocparser.pipeline_client",
        "iocparser.pipeline_worker",
        "iocparser.plugins",
        "iocparser.renderers",
        "iocparser.worker_config",
        "iocparser.worker_service",
    )
    # Allow bare "from iocparser import ..." re-exports in __init__.py
    bare_import_ok = {"iocparser"}
    assert all(
        imported in bare_import_ok or imported.startswith(allowed_prefixes) for imported in imports
    )

    for node in _top_level_nodes(path):
        assert not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)), (
            "__init__.py must stay a pure public re-export facade"
        )


def test_public_root_all_focuses_on_core_api_surface() -> None:
    root = REPO_ROOT / "iocparser" / "__init__.py"
    exports = ast.literal_eval(
        next(
            node.value
            for node in ast.parse(root.read_text(encoding="utf-8")).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
            )
        )
    )
    pipeline_exports = {
        "DistributedPipelineClient",
        "DistributedPipelineService",
        "DistributedWorkerService",
        "PipelineErrorInfo",
        "PipelineJobRequest",
        "PipelineJobResult",
        "PipelineWorker",
        "ResourceLimits",
        "WorkerServiceConfig",
        "create_queue_adapter",
        "default_queue_backend",
    }
    assert not (set(exports) & pipeline_exports)
    assert "__all__" not in pipeline_exports


def test_cli_facade_only_depends_on_cli_boundary_and_public_domain_types() -> None:
    path = IOCPARSER_ROOT / "cli.py"
    imports = _imports_for(path)
    allowed_prefixes = (
        "__future__",
        "argparse",
        "pathlib",
        "iocparser.cli_",
        "iocparser.domain.models",
        "iocparser.domain.enums",
        "iocparser.infrastructure.warninglists",
        "iocparser.errors",
        "iocparser",
    )
    assert all(
        imported == "iocparser" or imported.startswith(allowed_prefixes) for imported in imports
    ), f"cli.py imports unexpected modules for a facade: {sorted(imports)}"


def test_cli_boundary_owns_orchestration_of_concrete_adapters() -> None:
    cli_boundary_files = (
        IOCPARSER_ROOT / "cli.py",
        IOCPARSER_ROOT / "cli_args.py",
        IOCPARSER_ROOT / "cli_args_inputs.py",
        IOCPARSER_ROOT / "cli_args_parser.py",
        IOCPARSER_ROOT / "cli_args_values.py",
        IOCPARSER_ROOT / "cli_output.py",
        IOCPARSER_ROOT / "cli_output_rendering.py",
        IOCPARSER_ROOT / "cli_persistence.py",
        IOCPARSER_ROOT / "cli_processing.py",
        IOCPARSER_ROOT / "cli_processing_files.py",
        IOCPARSER_ROOT / "cli_processing_urls.py",
        IOCPARSER_ROOT / "cli_processing_urls_execution.py",
        IOCPARSER_ROOT / "cli_processing_single_support.py",
        IOCPARSER_ROOT / "cli_processing_single.py",
        IOCPARSER_ROOT / "cli_processing_support.py",
        IOCPARSER_ROOT / "cli_runtime.py",
        IOCPARSER_ROOT / "cli_schema.py",
    )
    cli_imports = set().union(*(_imports_for(path) for path in cli_boundary_files))
    assert "iocparser.application.use_cases" in cli_imports
    assert "iocparser.infrastructure.file_readers" in cli_imports
    assert "iocparser.infrastructure.http_download" in cli_imports


def test_boundaries_prefer_grouped_infrastructure_facades() -> None:
    boundary_limits = {
        IOCPARSER_ROOT / "distributed_pipeline.py": 0,
        IOCPARSER_ROOT / "worker_service.py": 0,
        IOCPARSER_ROOT / "pipeline_client.py": 0,
        IOCPARSER_ROOT / "cli_schema.py": 0,
    }
    for path, limit in boundary_limits.items():
        imports = _imports_for(path)
        direct_concrete = {
            imported
            for imported in imports
            if imported.startswith("iocparser.infrastructure.")
            and not imported.startswith(
                (
                    "iocparser.infrastructure.extraction",
                    "iocparser.infrastructure.persistence",
                    "iocparser.infrastructure.queueing",
                    "iocparser.infrastructure.runtime",
                )
            )
        }
        assert len(direct_concrete) <= limit, (
            f"{path.name} imports too many concrete infrastructure modules: {sorted(direct_concrete)}"
        )


def test_runtime_boundaries_do_not_use_root_runtime_helpers() -> None:
    boundaries = (
        IOCPARSER_ROOT / "distributed_pipeline.py",
        IOCPARSER_ROOT / "worker_service.py",
        IOCPARSER_ROOT / "pipeline_client.py",
    )
    forbidden = {"iocparser.telemetry", "iocparser.runtime_limits"}
    for path in boundaries:
        imports = _imports_for(path)
        assert not (imports & forbidden), (
            f"{path.name} should use iocparser.infrastructure.runtime instead of root runtime helpers: {sorted(imports & forbidden)}"
        )


def test_domain_and_application_avoid_io_and_process_shortcuts() -> None:
    protected_dirs = (
        IOCPARSER_ROOT / "domain",
        IOCPARSER_ROOT / "application",
    )
    forbidden_import_prefixes = ("requests", "sqlalchemy")
    forbidden_calls = {"print", "sys.exit"}

    for directory in protected_dirs:
        for path in directory.glob("*.py"):
            imports = _imports_for(path)
            calls = _call_names_for(path)
            assert not any(
                imported == prefix or imported.startswith(f"{prefix}.")
                for imported in imports
                for prefix in forbidden_import_prefixes
            ), f"{path.name} imports forbidden operational dependencies: {sorted(imports)}"
            assert not (calls & forbidden_calls), (
                f"{path.name} calls forbidden operational shortcuts: {sorted(calls)}"
            )


def test_print_is_confined_to_cli_boundary() -> None:
    allowed = {
        IOCPARSER_ROOT / "__main__.py",
        IOCPARSER_ROOT / "cli.py",
        IOCPARSER_ROOT / "cli_output.py",
        IOCPARSER_ROOT / "cli_output_rendering.py",
        IOCPARSER_ROOT / "cli_runtime.py",
    }
    for path in IOCPARSER_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or path in allowed:
            continue
        calls = _call_names_for(path)
        assert "print" not in calls, (
            f"{path.relative_to(REPO_ROOT)} uses print() outside the CLI boundary"
        )


def test_sys_exit_is_confined_to_entrypoint() -> None:
    allowed = IOCPARSER_ROOT / "__main__.py"
    for path in IOCPARSER_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or path == allowed:
            continue
        calls = _call_names_for(path)
        assert "sys.exit" not in calls, (
            f"{path.relative_to(REPO_ROOT)} uses sys.exit() outside __main__.py"
        )


def test_modules_package_is_removed() -> None:
    assert not (IOCPARSER_ROOT / "modules").exists()


def test_repository_no_longer_imports_modules_package() -> None:
    governed_roots = (IOCPARSER_ROOT, REPO_ROOT / "tests")
    for root in governed_roots:
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            imports = _imports_for(path)
            assert not any(
                imported == "iocparser.modules" or imported.startswith("iocparser.modules.")
                for imported in imports
            ), (
                f"{path.relative_to(REPO_ROOT)} still imports removed modules package: {sorted(imports)}"
            )


def test_public_root_does_not_advertise_removed_root_classes() -> None:
    root = REPO_ROOT / "iocparser" / "__init__.py"
    exports = ast.literal_eval(
        next(
            node.value
            for node in ast.parse(root.read_text(encoding="utf-8")).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
            )
        )
    )
    removed_exports = {
        "IOCExtractor",
        "PDFParser",
        "HTMLParser",
        "MISPWarningLists",
        "JSONFormatter",
        "TextFormatter",
        "STIXFormatter",
    }
    assert not (set(exports) & removed_exports)


def test_worker_config_does_not_depend_on_modules_config() -> None:
    path = IOCPARSER_ROOT / "worker_config.py"
    imports = _imports_for(path)
    assert "iocparser.config" not in imports
    assert "iocparser.worker_config_support" in imports


def test_hotspots_stay_within_decision_point_budget() -> None:
    budgets = {
        IOCPARSER_ROOT / "pipeline_worker.py": 20,
        IOCPARSER_ROOT / "worker_config.py": 12,
        IOCPARSER_ROOT / "infrastructure" / "streaming.py": 36,
        IOCPARSER_ROOT / "infrastructure" / "persistence_schema.py": 4,
        IOCPARSER_ROOT / "infrastructure" / "persistence_migrations.py": 6,
        # 19 (was 18): mark_running gained a terminal-state guard (one extra BoolOp) so a
        # redelivered already-completed/dead-lettered job is not resurrected to running.
        IOCPARSER_ROOT / "infrastructure" / "persistence_distributed.py": 19,
    }
    for path, limit in budgets.items():
        decisions = _decision_points_for(path)
        assert decisions <= limit, (
            f"{path.relative_to(REPO_ROOT)} is too complex ({decisions} > {limit})"
        )


def test_public_api_compatibility_doc_exists_and_references_canonical_modules() -> None:
    path = REPO_ROOT / "docs" / "API_COMPATIBILITY.md"
    content = path.read_text(encoding="utf-8")
    assert "iocparser.api_extraction" in content
    assert "iocparser.api_persistence" in content
    assert "iocparser.api_pipeline" in content


def test_root_runtime_limits_is_thin_fascade() -> None:
    from iocparser.infrastructure.runtime.limits import runtime_limits_guard

    assert callable(runtime_limits_guard)
