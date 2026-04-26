# Public API Compatibility Policy

Version: `1`

## Stable Public Modules

These modules are the supported public Python API surface:

- `iocparser.api_extraction`
- `iocparser.api_persistence`
- `iocparser.api_pipeline`

The package root `iocparser` is a convenience facade. It may re-export stable symbols, but new integrations should prefer the explicit `api_*` modules.

## Public CLI Surface

The supported command-line entrypoints are:

- `iocparser`
- `iocparser-worker`

CLI flags documented in the README are part of the public operational surface.

## Public Data Contracts

The following machine-to-machine contracts are public and versioned:

- result payloads
- batch reports
- pipeline job payloads
- distributed job records
- JSON Schemas shipped in `iocparser/schemas`

Breaking changes to these contracts require:

1. incrementing the relevant `schema_version`
2. updating the changelog/compatibility note
3. documenting the migration impact in release notes

## Internal Modules

These modules are implementation details and may change without compatibility guarantees:

- `iocparser.application.*`
- `iocparser.interfaces.*`
- `iocparser.adapters.*`
- `iocparser.infrastructure.*`
- `iocparser.cli_*`
- `iocparser.worker_*`
- `iocparser.pipeline_worker*`
- `iocparser.runtime_*`

Tests may import internal modules, but external consumers should not rely on them as stable APIs.

## Compatibility Rules

- Additive changes to public dataclasses, schemas, and outputs are preferred.
- Removing or renaming a public symbol from an `api_*` module is a breaking change.
- Narrowing the package root `iocparser.__all__` is allowed if the stable symbol remains available from the canonical `api_*` module.
- New public API should land in one of the `api_*` modules first, not directly in `iocparser.__init__`.

## Review Requirements

Changes touching public API require explicit review for:

- compatibility impact
- schema/version impact
- documentation updates
- tests covering both canonical `api_*` usage and any root-facade convenience exposure
