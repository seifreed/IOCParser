from __future__ import annotations

from pathlib import Path

from iocparser.domain.models import ExtractionOptions
from iocparser.infrastructure.file_readers import detect_file_type, read_text_content


def test_detect_file_type_falls_back_to_extension_for_missing_file(tmp_path: Path) -> None:
    missing_html = tmp_path / "missing.html"

    assert detect_file_type(missing_html) == "html"


def test_read_text_content_reads_plain_text(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("IOC domain: example.com", encoding="utf-8")

    assert read_text_content(str(sample), ExtractionOptions(file_type="text")) == "IOC domain: example.com"
