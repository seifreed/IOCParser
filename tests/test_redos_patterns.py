"""Regression tests for ReDoS vulnerabilities in regex patterns."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time

import pytest

from iocparser.infrastructure.extractor_patterns import PATTERNS

MAX_SECONDS = 1.0
SUBPROCESS_TIMEOUT_SECONDS = 10.0


def _alarm_handler(_signum: int, _frame: object) -> None:
    raise TimeoutError("Pattern took too long - probable ReDoS")


def _findall_with_subprocess_timeout(pattern_name: str, payload: str) -> float:
    script = (
        "import json\n"
        "import sys\n"
        "import time\n"
        "from iocparser.infrastructure.extractor_patterns import PATTERNS\n"
        "pattern = PATTERNS[sys.argv[1]]\n"
        "start = time.perf_counter()\n"
        "pattern.findall(sys.argv[2])\n"
        "print(json.dumps({'elapsed': time.perf_counter() - start}))"
    )
    try:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script, pattern_name, payload],
            capture_output=True,
            check=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Pattern took too long - probable ReDoS") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or repr(exc)
        raise RuntimeError(detail) from exc
    try:
        payload_obj = json.loads(completed.stdout)
        return float(payload_obj["elapsed"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            f"Pattern subprocess returned invalid output: {completed.stdout!r}"
        ) from exc


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
