"""Regression tests for ReDoS vulnerabilities in regex patterns."""

from __future__ import annotations

import multiprocessing
import queue
import signal
import time

import pytest

from iocparser.infrastructure.extractor_patterns import PATTERNS

MAX_SECONDS = 1.0
SUBPROCESS_TIMEOUT_SECONDS = 10.0


def _alarm_handler(_signum: int, _frame: object) -> None:
    raise TimeoutError("Pattern took too long - probable ReDoS")


def _findall_in_child(pattern_name: str, payload: str, results: multiprocessing.Queue) -> None:
    try:
        pattern = PATTERNS[pattern_name]
        start = time.perf_counter()
        pattern.findall(payload)
        results.put(("ok", time.perf_counter() - start))
    except BaseException as exc:
        results.put(("error", repr(exc)))


def _findall_with_subprocess_timeout(pattern_name: str, payload: str) -> float:
    ctx = multiprocessing.get_context("spawn")
    results = ctx.Queue()
    process = ctx.Process(target=_findall_in_child, args=(pattern_name, payload, results))
    process.start()
    process.join(SUBPROCESS_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        raise TimeoutError("Pattern took too long - probable ReDoS")
    try:
        status, value = results.get(timeout=1)
    except queue.Empty as exc:
        raise RuntimeError(
            f"Pattern subprocess exited without a result: {process.exitcode}"
        ) from exc
    if status == "error":
        raise RuntimeError(str(value))
    return float(value)


@pytest.mark.parametrize(
    ("pattern_name", "payload"),
    [
        # YARA: many unmatched braces should not backtrack forever
        pytest.param(
            "yara",
            "rule x {\n" + "{" * 500 + "\n}",
            id="yara_unmatched_braces",
        ),
        # Snort: very long line without semicolon delimiter
        pytest.param(
            "snort_rules",
            "alert tcp " + "A" * 2000,
            id="snort_long_line_no_semicolon",
        ),
        # Sigma: long block without detection keyword
        pytest.param(
            "sigma_rules",
            "title: foo\n" + ("foo: bar\n" * 200),
            id="sigma_long_block_no_detection",
        ),
        # Docker: repeated punctuation before digest
        pytest.param(
            "docker_images",
            "a." * 500 + "@sha256:" + "a" * 64,
            id="docker_repeated_punctuation",
        ),
        # Domains: long defanged domain
        pytest.param(
            "domains",
            "a" + "[.]" * 500 + "com",
            id="domains_long_defanged",
        ),
        # Filepaths: very deep Windows path
        pytest.param(
            "filepaths",
            "C:\\" + "a\\" * 500,
            id="filepaths_deep_windows",
        ),
        # PDB paths: very deep PDB path
        pytest.param(
            "pdb_paths",
            "C:\\" + "a\\" * 500 + "x.pdb",
            id="pdb_paths_deep_windows",
        ),
    ],
)
def test_pattern_does_not_redos(pattern_name: str, payload: str) -> None:
    """Ensure critical regex patterns complete within MAX_SECONDS."""
    pattern = PATTERNS[pattern_name]

    # Use alarm where available (Unix) for hard timeout
    if hasattr(signal, "SIGALRM"):
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(MAX_SECONDS) + 1)
        try:
            start = time.perf_counter()
            pattern.findall(payload)
            elapsed = time.perf_counter() - start
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        elapsed = _findall_with_subprocess_timeout(pattern_name, payload)

    assert elapsed < MAX_SECONDS, f"{pattern_name} took {elapsed:.2f}s - probable ReDoS"


def test_subprocess_timeout_fallback_runs_fast_pattern() -> None:
    elapsed = _findall_with_subprocess_timeout("domains", "example.com")
    assert elapsed < MAX_SECONDS
