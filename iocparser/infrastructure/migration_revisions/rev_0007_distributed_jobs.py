from __future__ import annotations

from sqlalchemy import Engine, Inspector


def apply(engine: Engine, inspector: Inspector) -> None:
    """Add distributed job lifecycle and dead-letter tables."""
    table_names = set(inspector.get_table_names())
    statements: list[str] = []
    if "distributed_jobs" not in table_names:
        statements.extend(
            (
                """
                CREATE TABLE distributed_jobs (
                    id INTEGER PRIMARY KEY,
                    job_id VARCHAR(128) NOT NULL UNIQUE,
                    correlation_id VARCHAR(128) NOT NULL,
                    queue_backend VARCHAR(32) NOT NULL,
                    queue_name VARCHAR(128) NOT NULL,
                    input_kind VARCHAR(16) NOT NULL,
                    source_value TEXT NOT NULL,
                    idempotency_key VARCHAR(128),
                    status VARCHAR(24) NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    retryable BOOLEAN,
                    receipt_id VARCHAR(256),
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    metrics_json TEXT NOT NULL DEFAULT '{}',
                    last_error_code VARCHAR(64),
                    last_error_category VARCHAR(64),
                    last_error_message TEXT,
                    run_id INTEGER,
                    submitted_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    dead_lettered_at TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                )
                """,
                "CREATE INDEX IF NOT EXISTS ix_distributed_jobs_status_submitted ON distributed_jobs(status, submitted_at)",
                "CREATE INDEX IF NOT EXISTS ix_distributed_jobs_backend_status ON distributed_jobs(queue_backend, status)",
                "CREATE INDEX IF NOT EXISTS ix_distributed_jobs_correlation ON distributed_jobs(correlation_id)",
                "CREATE INDEX IF NOT EXISTS ix_distributed_jobs_idempotency ON distributed_jobs(idempotency_key)",
            ),
        )
    if "dead_letter_jobs" not in table_names:
        statements.extend(
            (
                """
                CREATE TABLE dead_letter_jobs (
                    id INTEGER PRIMARY KEY,
                    job_id VARCHAR(128) NOT NULL,
                    correlation_id VARCHAR(128) NOT NULL,
                    queue_backend VARCHAR(32) NOT NULL,
                    queue_name VARCHAR(128) NOT NULL,
                    source_value TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    error_code VARCHAR(64) NOT NULL,
                    error_category VARCHAR(64) NOT NULL,
                    error_message TEXT NOT NULL,
                    retryable BOOLEAN NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    dead_lettered_at TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS ix_dead_letter_jobs_backend_created ON dead_letter_jobs(queue_backend, dead_lettered_at)",
                "CREATE INDEX IF NOT EXISTS ix_dead_letter_jobs_job_id ON dead_letter_jobs(job_id)",
            ),
        )
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)
