# Architecture Rules

## Layers

- `iocparser/domain`
  Contains value objects and normalized result models.
- `iocparser/application`
  Contains use cases and input DTOs.
- `iocparser/interfaces`
  Contains ports used by the application layer.
- `iocparser/adapters`
  Contains presentation/output adapters that translate normalized models.
- `iocparser/infrastructure`
  Contains concrete implementations for file reading, HTTP, warning lists, persistence, queueing, runtime, and filesystem output.
- `iocparser/infrastructure/extraction`, `iocparser/infrastructure/persistence`, `iocparser/infrastructure/queueing`, `iocparser/infrastructure/runtime`
  Are the grouped infrastructure entry points. Boundaries should prefer these over importing many flat infrastructure modules directly.
- The repo is also organized by bounded contexts: extraction, persistence/analysis, and pipeline/distributed runtime. See `docs/BOUNDED_CONTEXTS.md`.
- `iocparser/cli.py`
  Is a thin public facade for the command-line interface.
- `iocparser/cli_args.py`, `iocparser/cli_processing.py`, `iocparser/cli_output.py`, `iocparser/cli_runtime.py`
  Form the CLI boundary implementation. Keep parsing, orchestration, presentation, and runtime wiring split across these modules.
- `iocparser/api_extraction.py`, `iocparser/api_persistence.py`, `iocparser/api_pipeline.py`
  Are the canonical stable Python API surface. Prefer these over `iocparser.__init__` in new integrations.
- `iocparser/__init__.py`
  Is a convenience re-export facade only. Keep it narrower than the canonical `api_*` modules.

## Dependency Rules

- `domain` must not import `application`, `adapters`, `infrastructure`, or `cli`.
- `application` must depend on `domain` and `interfaces`, not on `infrastructure` or `adapters`.
- `infrastructure` may depend on `domain` and `interfaces`.
- `adapters` may depend on `domain` and `interfaces`.
- `cli.py` may wire together concrete adapters and call application use cases.
- `cli.py` and `domain/models.py` must remain facade-level modules with no substantial business logic.
- `domain/models.py` is a pure re-export facade.
- `cli.py` is a public facade over the CLI boundary modules.
- `print()` is allowed only in the CLI boundary.
- `sys.exit()` is allowed only in `iocparser/__main__.py`.
- `requests` and `sqlalchemy` must stay out of `domain` and `application`.
- Removed legacy facades such as `core.py`, `download.py`, `extraction.py`, `main.py`, and the old `modules/` package must not be reintroduced.

## Dependency Diagram

```text
cli
  -> application
  -> adapters
  -> infrastructure

application
  -> domain
  -> interfaces

adapters
  -> domain
  -> interfaces

infrastructure
  -> domain
  -> interfaces

domain
  -> (no outer layer)
```

## Working Rules

- New behavior must land in `domain`, `application`, `interfaces`, `adapters`, or `infrastructure`.
- `application` must not import concrete infrastructure or output adapters.
- `domain` must not import outer layers.
- New boundary wiring should prefer grouped infrastructure subpackages over flat infrastructure modules.
- Tests in `tests/test_architecture.py` enforce the dependency boundaries and basic module-size limits.
- Tests in `tests/test_architecture.py` also enforce facade purity, grouped-infrastructure limits, and the absence of the removed `modules/` package.
- `make arch-guard` runs the architecture-specific guardrails locally.
- CI must run lint, type-checking, and the architecture tests on every PR.
- CI must run a fast functional lane first, then the full covered functional lane.
- The default pytest path excludes `benchmark` tests; benchmarks must run only through explicit commands and the dedicated manual CI job.
- Tests marked `slow` remain part of the full functional suite, but are excluded from the fast lane only.
- Coverage enforcement for the functional suite is `100%`.

## Review Heuristics

Reject or move a change when:

- a facade starts owning real workflow or normalization logic,
- `domain` or `application` reaches out to HTTP, filesystem, SQLAlchemy, or CLI concerns,
- convenience shortcuts bypass ports or use cases.
- `domain/models.py` stops being a re-export-only module,
- `cli.py` starts doing parsing, rendering, downloading, persistence, or extraction work directly.
- `iocparser.__init__` becomes broader than the canonical `api_*` modules,
- a boundary imports many concrete infrastructure helpers instead of going through grouped infrastructure facades.
