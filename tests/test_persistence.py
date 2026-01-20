#!/usr/bin/env python3

"""
Tests for SQLite persistence.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from iocparser.modules.persistence import IOC, PersistenceManager, PersistOptions, Run, RunIOC


def test_persist_run_sqlite(tmp_path) -> None:
    """Persist a run in SQLite and verify records."""
    db_path = tmp_path / "iocparser.db"
    manager = PersistenceManager(f"sqlite:///{db_path}")

    normal_iocs = {
        "domains": ["example.com"],
        "md5": ["5f4dcc3b5aa765d61d8327deb882cf99"],
    }
    warning_iocs = {
        "domains": [
            {"value": "google.com", "warning_list": "top", "description": "popular"},
        ],
    }

    options = PersistOptions(
        defang=True,
        check_warnings=True,
        force_update=False,
        output_format="stix",
    )

    run_id = manager.persist_run(
        source_kind="url",
        source_value="https://example.com/report",
        normal_iocs=normal_iocs,
        warning_iocs=warning_iocs,
        tool_version="5.0.0",
        options=options,
    )

    with Session(manager.engine) as session:
        run = session.execute(select(Run).where(Run.id == run_id)).scalar_one()
        ioc_count = session.execute(select(IOC)).scalars().all()
        run_iocs = session.execute(select(RunIOC).where(RunIOC.run_id == run.id)).scalars().all()

    assert run.source_id is not None
    assert len(ioc_count) == 3
    assert len(run_iocs) == 3
