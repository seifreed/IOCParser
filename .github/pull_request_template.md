## Summary

- What changed?
- Why does this belong in this layer?
- Which bounded context is primary (`extraction`, `persistence/analysis`, or `pipeline/runtime`)?

## Architecture Checklist

- [ ] New domain rules, enums, value objects, or normalization live in `iocparser/domain`.
- [ ] New use-case orchestration lives in `iocparser/application`.
- [ ] New ports or dependency contracts live in `iocparser/interfaces`.
- [ ] New external integrations, rendering details, filesystem, HTTP, database, or framework code live in `iocparser/adapters` or `iocparser/infrastructure`.
- [ ] `iocparser/cli.py` and `iocparser/domain/models.py` remain thin facades only.
- [ ] `iocparser/domain/models.py` is still a re-export-only facade.
- [ ] `iocparser/cli.py` still delegates real work to `cli_args`, `cli_processing`, `cli_output`, or `cli_runtime`.
- [ ] Public Python API changes landed in `iocparser/api_extraction.py`, `iocparser/api_persistence.py`, or `iocparser/api_pipeline.py` first.
- [ ] `iocparser.__init__` was kept as a narrow convenience facade.
- [ ] I did not introduce `print()` outside the CLI boundary or `sys.exit()` outside `iocparser/__main__.py`.
- [ ] I did not import `requests` or `sqlalchemy` into `iocparser/domain` or `iocparser/application`.
- [ ] I updated `tests/test_architecture.py` if I changed a dependency boundary or added a new rule.
- [ ] `make test-quick`, `make arch-guard`, and `make test` pass locally.

## Risk Review

- [ ] Public API compatibility checked
- [ ] Changes under `iocparser/application`, `iocparser/interfaces`, `iocparser/infrastructure/*`, or `iocparser/api_*` received explicit architecture review
- [ ] Persistence or schema impact checked
- [ ] Output/rendering impact checked
- [ ] Docs updated if a new extension point or boundary changed
