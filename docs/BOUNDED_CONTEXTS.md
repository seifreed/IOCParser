# Bounded Contexts

Version: `1`

The repo is intentionally broader than a single-file IOC extractor. To keep that scope clean, code is organized around three main bounded contexts.

## 1. Extraction

Owns:

- text/file/url ingestion
- parsing
- IOC extraction
- warning-list enrichment
- rendering-ready normalized results

Primary modules:

- `iocparser.api_extraction`
- `iocparser.application.use_cases`
- `iocparser.infrastructure.extraction`

## 2. Persistence and Analysis

Owns:

- persisted runs
- queries
- diffs
- history maintenance
- migrations
- search/FTS

Primary modules:

- `iocparser.api_persistence`
- `iocparser.application.query_use_cases`
- `iocparser.application.maintenance_use_cases`
- `iocparser.infrastructure.persistence`

## 3. Pipeline and Distributed Runtime

Owns:

- pipeline jobs
- queue adapters
- distributed worker lifecycle
- runtime guards
- telemetry sinks

Primary modules:

- `iocparser.api_pipeline`
- `iocparser.application.distributed_use_cases`
- `iocparser.infrastructure.queueing`
- `iocparser.infrastructure.runtime`

## Rule of Thumb

When a change touches more than one bounded context, the PR should say which context is primary and why the other context is only supporting it.

If a change starts to create generic “helper” modules spanning all contexts, stop and split by ownership instead.
