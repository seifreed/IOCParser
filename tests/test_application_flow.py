from pathlib import Path

from iocparser.api_extraction import extract_iocs_from_file, extract_iocs_from_text
from iocparser.application.contracts import ExtractFileInput, ExtractTextInput
from iocparser.application.use_cases import (
    extract_from_file,
)
from iocparser.application.use_cases import (
    extract_from_text as shared_extract_iocs_from_text,
)
from iocparser.domain.models import ExtractionOptions
from iocparser.infrastructure.extraction import DefaultIOCExtractionEngine
from iocparser.infrastructure.file_readers import MagicTextSourceReader

_reader = MagicTextSourceReader()


def test_library_api_reuses_shared_file_processing_flow(tmp_path: Path) -> None:
    sample = tmp_path / "shared-flow.txt"
    sample.write_text("IOC domain: shared-flow.example\nIP: 203.0.113.10\n", encoding="utf-8")

    shared_result = extract_from_file(
        ExtractFileInput(
            file_path=str(sample),
            options=ExtractionOptions(file_type="text", defang=False, check_warnings=False),
        ),
        reader=_reader,
        extractor_engine=DefaultIOCExtractionEngine(),
    )
    expected = shared_result.grouped_iocs(), shared_result.grouped_warnings()
    result = extract_iocs_from_file(sample, file_type="text", defang=False, check_warnings=False)

    assert result == expected


def test_library_text_api_reuses_shared_text_extraction_flow() -> None:
    text = "IOC URL: https://example.test/path and email a@b.test"

    shared_result = shared_extract_iocs_from_text(
        ExtractTextInput(
            text_content=text,
            options=ExtractionOptions(defang=False, check_warnings=False),
        ),
        extractor_engine=DefaultIOCExtractionEngine(),
    )
    expected = shared_result.grouped_iocs(), shared_result.grouped_warnings()
    result = extract_iocs_from_text(text, defang=False, check_warnings=False)

    assert result == expected
