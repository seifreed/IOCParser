from __future__ import annotations

import argparse

from iocparser._version import resolve_version

VERSION = resolve_version()
MAX_WORKERS = 4
DEFAULT_URL_WORKERS = 4


POSITIVE_INT_REQUIRED = "must be a positive integer, got {value}"
NON_NEGATIVE_INT_REQUIRED = "must be zero or a positive integer, got {value}"


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError(POSITIVE_INT_REQUIRED.format(value=parsed))
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError(NON_NEGATIVE_INT_REQUIRED.format(value=parsed))
    return parsed


def _add_input_arguments(parser: argparse.ArgumentParser) -> None:
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-f", "--file", help="Path to the file to analyze")
    input_group.add_argument("-u", "--url", help="URL of the report to analyze")
    input_group.add_argument("-m", "--multiple", nargs="+", help="Multiple files to analyze")
    input_group.add_argument("-d", "--directory", help="Directory containing files to analyze")
    input_group.add_argument("--url-file", help="File containing URLs to analyze, one per line")
    input_group.add_argument(
        "--retry-failed-from", help="Retry failed URLs from a prior batch report JSON file"
    )
    # An input source like --retry-failed-from: keep it mutually exclusive with the
    # other inputs so it cannot silently override -f/-u/-m/-d/--url-file.
    input_group.add_argument(
        "--retry-batch-job", type=int, help="Retry failed URLs from a persisted batch job"
    )
    input_group.add_argument("--stdin", action="store_true", help="Read input text from stdin")
    input_group.add_argument("url_direct", nargs="?", help="Direct URL as positional argument")


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", help="Output file path (use - for stdout)")
    parser.add_argument(
        "-t", "--type", choices=["pdf", "html", "text"], help="Force specific file type"
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Output in JSON format")
    output_group.add_argument("--jsonl", action="store_true", help="Output in JSON Lines format")
    output_group.add_argument("--csv", action="store_true", help="Output in CSV format")
    output_group.add_argument("--stix", action="store_true", help="Output in STIX 2.1 format")
    parser.add_argument("--stix-types", help="Comma-separated IOC types to include in STIX output")
    parser.add_argument("--renderer", help="Registered renderer plugin name to use for output")
    parser.add_argument(
        "--with-context", action="store_true", help="Include context/evidence in rich outputs"
    )
    parser.add_argument(
        "--summary", action="store_true", help="Show a compact analyst summary in text output"
    )


def _add_processing_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--search-backend",
        choices=["auto", "fts", "like"],
        default="auto",
        help="Search backend for persisted IOC queries",
    )
    parser.add_argument("--only", help="Comma-separated IOC types to include")
    parser.add_argument("--exclude", help="Comma-separated IOC types to exclude")
    parser.add_argument("--severity", help="Comma-separated severities to include")
    parser.add_argument("--tag", help="Comma-separated tags to include")
    parser.add_argument("--ioc-type", help="IOC type filter for persisted queries and diffs")
    parser.add_argument(
        "--only-warnings", action="store_true", help="Show only warning-list matches"
    )
    parser.add_argument("--only-normal", action="store_true", help="Show only normal IOCs")
    parser.add_argument(
        "--sort-by",
        choices=["type", "value", "severity"],
        default="type",
        help="Sort analyst-facing output",
    )
    parser.add_argument(
        "--max-evidence", type=int, help="Limit the number of evidence excerpts per IOC"
    )
    parser.add_argument(
        "--streaming", action="store_true", help="Use streaming extraction for file inputs"
    )
    parser.add_argument(
        "--chunk-size",
        type=_positive_int,
        default=None,
        help="Chunk size for streaming extraction",
    )
    parser.add_argument(
        "--overlap",
        type=_non_negative_int,
        default=None,
        help="Chunk overlap for streaming extraction",
    )
    parser.add_argument(
        "--recursive", action="store_true", help="Recurse into subdirectories in directory mode"
    )
    parser.add_argument("--glob", default="*", help="Glob pattern for directory mode")
    parser.add_argument("--no-defang", action="store_true", help="Disable automatic defanging")
    parser.add_argument(
        "--no-check-warnings", action="store_true", help="Don't check against MISP warning lists"
    )
    parser.add_argument(
        "--force-update", action="store_true", help="Force update of MISP warning lists"
    )
    parser.add_argument(
        "--enricher", action="append", help="Registered enricher plugin name (repeatable)"
    )
    parser.add_argument(
        "--extractor", action="append", help="Registered extractor plugin name (repeatable)"
    )
    parser.add_argument(
        "--postprocessor", action="append", help="Registered postprocessor plugin name (repeatable)"
    )
    parser.add_argument(
        "--list-plugins", action="store_true", help="List registered plugin names and exit"
    )
    parser.add_argument("--init", action="store_true", help="Initialize MISP warning lists")


def _add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--log-file", help="Path to log file")
    parser.add_argument("--version", action="version", version=f"IOCParser v{VERSION}")
    parser.add_argument(
        "--parallel",
        type=int,
        default=None,
        help=f"Parallel workers for multiple files (default 1 = serial; e.g. {MAX_WORKERS})",
    )
    parser.add_argument(
        "--url-workers",
        type=int,
        default=None,
        help="Parallel workers for URL batch inputs",
    )
    parser.add_argument(
        "--url-retries", type=int, default=None, help="Retries for URL batch downloads"
    )
    parser.add_argument(
        "--url-backoff",
        type=float,
        default=None,
        help="Base backoff in seconds between URL retries",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Minimum delay in seconds between URL requests",
    )
    parser.add_argument("--user-agent", help="HTTP User-Agent for URL downloads")
    parser.add_argument(
        "--header", action="append", help="Extra HTTP header in the form Name: Value"
    )
    parser.add_argument("--cookie", action="append", help="HTTP cookie in the form name=value")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument(
        "--allow-redirects",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Follow HTTP redirects",
    )
    parser.add_argument(
        "--tls-verify",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable TLS certificate verification",
    )
    parser.add_argument("--tls-cert", help="Client TLS certificate path for URL downloads")
    parser.add_argument("--ca-bundle", help="CA bundle path for TLS verification")
    parser.add_argument(
        "--allow-private-urls",
        action="store_true",
        default=False,
        help="Allow downloading URLs that resolve to private/loopback/reserved addresses "
        "(disables the SSRF guard)",
    )
    parser.add_argument(
        "--connect-timeout", type=float, help="Connection timeout for URL downloads"
    )
    parser.add_argument("--read-timeout", type=float, help="Read timeout for URL downloads")
    parser.add_argument(
        "--job-id", help="Explicit pipeline job identifier for machine-readable reports"
    )
    parser.add_argument(
        "--correlation-id", help="Correlation identifier for upstream pipeline tracing"
    )
    parser.add_argument(
        "--skip-processed",
        action="store_true",
        help="Skip persistence and extraction when the input fingerprint already exists",
    )
    parser.add_argument(
        "--max-input-size-mb",
        type=float,
        help="Maximum input size in MB for pipeline/worker execution",
    )
    parser.add_argument(
        "--max-input-seconds", type=float, help="Maximum processing time per input in seconds"
    )
    parser.add_argument(
        "--max-queue-size",
        type=int,
        default=None,
        help="Maximum in-flight queue size for worker-style integration",
    )


def _add_persistence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--persist",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable persistence (uses config/env if not set)",
    )
    parser.add_argument("--db-uri", help="Database URI for persistence")
    parser.add_argument("--config", help="Path to config file (INI)")
    parser.add_argument("--list-runs", action="store_true", help="List persisted runs")
    parser.add_argument("--run-limit", type=int, default=20, help="Number of runs to list")
    parser.add_argument("--search-ioc", help="Search persisted IOCs by value")
    parser.add_argument("--date-from", help="Filter persisted queries from ISO date/datetime")
    parser.add_argument("--date-to", help="Filter persisted queries to ISO date/datetime")
    parser.add_argument("--source-kind", help="Filter persisted queries by source kind")
    parser.add_argument("--source-value", help="Filter persisted queries by source value")
    parser.add_argument(
        "--diff-runs",
        nargs=2,
        type=int,
        metavar=("LEFT", "RIGHT"),
        help="Diff two persisted run IDs",
    )
    parser.add_argument(
        "--diff-latest", type=int, help="Diff a run against the previous run from the same source"
    )
    parser.add_argument(
        "--diff-only",
        choices=["all", "added", "removed"],
        default=None,
        help="Limit diff output sections",
    )
    parser.add_argument(
        "--diff-warnings-only", action="store_true", help="Only include warning entries in diffs"
    )
    parser.add_argument("--export-run", type=int, help="Export a persisted run by ID")
    parser.add_argument(
        "--offset", type=int, default=0, help="Offset for persisted run or IOC queries"
    )
    parser.add_argument(
        "--query-limit", type=int, default=50, help="Result limit for persisted IOC searches"
    )
    parser.add_argument(
        "--query-sort",
        choices=["newest", "oldest", "source"],
        default="newest",
        help="Sort order for persisted queries",
    )
    parser.add_argument(
        "--exclude-tag", action="append", help="Tags to exclude from persisted searches"
    )
    parser.add_argument(
        "--tag-mode",
        choices=["all", "any"],
        default="all",
        help="How tags are matched in persisted searches",
    )
    parser.add_argument(
        "--min-severity",
        choices=["informational", "low", "medium", "high"],
        help="Minimum severity for persisted searches",
    )
    parser.add_argument("--delete-run", type=int, help="Delete a persisted run by ID")
    parser.add_argument("--prune-before", help="Delete persisted runs before an ISO date/datetime")
    parser.add_argument(
        "--keep-latest", type=int, default=0, help="Keep this many newest runs when pruning"
    )
    parser.add_argument(
        "--prune-status", action="append", help="Limit prune/retention to run statuses"
    )
    parser.add_argument(
        "--retain-days", type=int, help="Retention policy in days for persisted runs"
    )
    parser.add_argument(
        "--export-history", help="Export full persisted history to JSON (- for stdout)"
    )
    parser.add_argument("--import-history", help="Import full persisted history from JSON")
    parser.add_argument("--archive-history", help="Archive full persisted history to JSON")
    parser.add_argument(
        "--restore-history", help="Restore full persisted history from a JSON archive"
    )
    parser.add_argument(
        "--compact-history", action="store_true", help="Compact the persistence database"
    )
    parser.add_argument(
        "--schema-version", action="store_true", help="Show persistence schema version"
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Migrate the persistence schema to the latest version",
    )
    parser.add_argument(
        "--validate-schema", action="store_true", help="Validate persistence schema drift"
    )


def _add_batch_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--batch-report-json",
        nargs="?",
        const="-",
        help="Write URL batch report as JSON (stdout if no path given)",
    )
    parser.add_argument(
        "--list-failed-batches", action="store_true", help="List recent failed batch jobs"
    )
    parser.add_argument(
        "--list-batches", action="store_true", help="List recent persisted batch jobs"
    )
    parser.add_argument("--batch-job", type=int, help="Show details for a persisted batch job")
    parser.add_argument("--batch-runs", type=int, help="List persisted runs for a batch job")
    parser.add_argument(
        "--batch-limit", type=int, default=20, help="Limit for failed-batch listings"
    )
    parser.add_argument(
        "--retry-error-type", help="Only retry failed batch items for this error type"
    )
    parser.add_argument(
        "--retry-error-contains", help="Only retry failed batch items containing this error text"
    )


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Indicators of Compromise (IOCs) Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_input_arguments(parser)
    _add_output_arguments(parser)
    _add_processing_arguments(parser)
    _add_runtime_arguments(parser)
    _add_persistence_arguments(parser)
    _add_batch_arguments(parser)
    return parser
