# AGENTS.md

Guidance for AI coding agents working in this repository.

## Coverage Policy

- Do not add `# pragma: no cover` to production code or tests.
- Do not fix coverage failures by adding coverage exclusions.
- When CI requires 100% coverage, add meaningful tests for observable behavior or refactor unreachable/dead code so the coverage contract remains honest.
