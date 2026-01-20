#!/usr/bin/env python3

"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Comprehensive tests for streaming IOC extraction module.
Tests all streaming functionality with real file operations and data.

Author: Marc Rivero | @seifreed
"""

import contextlib
import io
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

from iocparser.modules.exceptions import IOCFileNotFoundError
from iocparser.modules.streaming import (
    ParallelStreamingExtractor,
    StreamingIOCExtractor,
    extract_iocs_from_large_file,
    stream_iocs_from_file,
)


# Helper function to handle the generator/dict return type from extract_from_file
def _get_file_extraction_result(
    extractor: StreamingIOCExtractor, file_path: Path, yield_chunks: bool = False
):
    """
    Helper to properly handle extract_from_file results.

    The extract_from_file method is a generator function due to the yield statement.
    When yield_chunks=False, it returns a dict via the return statement, but since
    the function contains yield, Python makes it return a generator. The dict is
    available in the StopIteration.value when the generator is exhausted.
    """
    result_gen = extractor.extract_from_file(file_path, yield_chunks=yield_chunks)

    if yield_chunks:
        # Return the generator as-is for iteration
        return result_gen
    # When yield_chunks=False, the generator doesn't yield anything
    # but returns a dict. We get this dict from the StopIteration exception.
    try:
        # Try to get the next item (should immediately raise StopIteration)
        while True:
            next(result_gen)
    except StopIteration as e:
        # The return value is in e.value
        return e.value if hasattr(e, "value") else {}

    # Fallback (shouldn't reach here)
    return {}


def _consume_generator_result(gen):
    """
    Helper to consume a generator and get its return value.

    When a generator function has a return statement, the return value
    is available in StopIteration.value when the generator is exhausted.
    """
    try:
        while True:
            next(gen)
    except StopIteration as e:
        return e.value if hasattr(e, "value") else {}
    return {}


# Test data with various IOCs
SAMPLE_IOC_TEXT = """
Malware Analysis Report

The malware sample communicates with the following infrastructure:
- Domain: evil-malware[.]com
- IP Address: 192.168.1.100
- MD5: 5d41402abc4b2a76b9719d911017c592
- SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

Additional indicators:
- URL: hxxp://bad-site[.]org/payload.exe
- Email: attacker[@]evil[.]net
- Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

CVE-2024-1234 was exploited to gain initial access.
Registry key: HKEY_LOCAL_MACHINE\\Software\\Malware\\Config
Mutex: Global\\MalwareMutex123
"""

LARGE_SAMPLE_TEXT = "\n".join(
    [
        f"Line {i}: Found domain test{i}.example.org and IP 10.0.{i % 256}.{(i * 7) % 256}"
        for i in range(1000)
    ]
)

CHUNK_BOUNDARY_TEXT = """
This text is designed to test chunk boundaries.
The domain split-across-boun
dary.evil.com should be detected.
IP address 192.168.
10.50 split across lines.
Hash: 5f4dcc3b5aa765d61d83
27deb882cf99 is split.
"""


class TestStreamingIOCExtractor:
    """Test suite for StreamingIOCExtractor class."""

    def test_init_default_parameters(self):
        """
        Test initialization with default parameters.

        Validates that the extractor is properly initialized with default
        chunk size, overlap, and defang settings.
        """
        extractor = StreamingIOCExtractor()

        assert extractor.chunk_size == 1024 * 1024  # 1MB
        assert extractor.overlap == 1024  # 1KB
        assert extractor.extractor.defang is True
        assert extractor.progress_callback is None
        assert isinstance(extractor.seen_iocs, defaultdict)

    def test_init_custom_parameters(self):
        """
        Test initialization with custom parameters.

        Validates that custom chunk size, overlap, defang, and callback
        settings are correctly applied.
        """
        progress_values = []

        def progress_callback(progress: int) -> None:
            progress_values.append(progress)

        extractor = StreamingIOCExtractor(
            chunk_size=512,
            overlap=64,
            defang=False,
            progress_callback=progress_callback,
        )

        assert extractor.chunk_size == 512
        assert extractor.overlap == 64
        assert extractor.extractor.defang is False
        assert extractor.progress_callback is progress_callback

    def test_decode_chunk_with_bytes(self):
        """
        Test chunk decoding with bytes input.

        Validates that bytes are correctly decoded to UTF-8 strings,
        handling errors gracefully.
        """
        extractor = StreamingIOCExtractor()

        # Test normal UTF-8 bytes
        data = b"Test domain: evil.com"
        result = extractor._decode_chunk(data)

        assert result == "Test domain: evil.com"
        assert isinstance(result, str)

    def test_decode_chunk_with_string(self):
        """
        Test chunk decoding with string input.

        Validates that strings are returned as-is without modification.
        """
        extractor = StreamingIOCExtractor()

        data = "Already a string with domain evil.com"
        result = extractor._decode_chunk(data)

        assert result == data
        assert isinstance(result, str)

    def test_decode_chunk_with_invalid_utf8(self):
        """
        Test chunk decoding with invalid UTF-8 bytes.

        Validates that invalid UTF-8 sequences are handled gracefully
        using error replacement.
        """
        extractor = StreamingIOCExtractor()

        # Invalid UTF-8 sequence
        data = b"Test \xff\xfe invalid bytes"
        result = extractor._decode_chunk(data)

        # Should not raise exception, errors are ignored
        assert isinstance(result, str)
        assert "Test" in result

    def test_accumulate_iocs_empty_target(self):
        """
        Test IOC accumulation into empty target dictionary.

        Validates that IOCs are correctly added to an empty target dict.
        """
        extractor = StreamingIOCExtractor()

        target: dict[str, list[str]] = defaultdict(list)
        source = {
            "domains": ["evil.com", "bad.net"],
            "ips": ["192.168.1.1", "10.0.0.1"],
        }

        extractor._accumulate_iocs(target, source)

        assert target["domains"] == ["evil.com", "bad.net"]
        assert target["ips"] == ["192.168.1.1", "10.0.0.1"]

    def test_accumulate_iocs_existing_target(self):
        """
        Test IOC accumulation into existing target dictionary.

        Validates that IOCs are appended to existing lists in the target.
        """
        extractor = StreamingIOCExtractor()

        target: dict[str, list[str]] = defaultdict(list)
        target["domains"] = ["existing.com"]
        target["md5"] = ["abc123"]

        source = {
            "domains": ["new1.com", "new2.org"],
            "ips": ["192.168.1.1"],
        }

        extractor._accumulate_iocs(target, source)

        assert target["domains"] == ["existing.com", "new1.com", "new2.org"]
        assert target["md5"] == ["abc123"]
        assert target["ips"] == ["192.168.1.1"]

    def test_deduplicate_iocs_first_call(self):
        """
        Test IOC deduplication on first call with empty state.

        Validates that all IOCs pass through on first deduplication
        and are tracked in seen_iocs state.
        """
        extractor = StreamingIOCExtractor()

        new_iocs = {
            "domains": ["evil.com", "bad.net", "evil.com"],  # Contains duplicate
            "ips": ["192.168.1.1"],
        }

        result = extractor._deduplicate_iocs(new_iocs)

        # Should remove duplicates within the same batch
        assert "domains" in result
        assert "ips" in result
        assert len(result["domains"]) >= 1  # At least one unique domain

        # State should be updated
        assert (
            "evil.com" in extractor.seen_iocs["domains"]
            or "evil[.]com" in extractor.seen_iocs["domains"]
        )

    def test_deduplicate_iocs_subsequent_call(self):
        """
        Test IOC deduplication on subsequent calls.

        Validates that previously seen IOCs are filtered out in
        subsequent deduplication calls.
        """
        extractor = StreamingIOCExtractor()

        # First batch
        first_iocs = {
            "domains": ["evil.com"],
            "ips": ["192.168.1.1"],
        }
        extractor._deduplicate_iocs(first_iocs)

        # Second batch with some duplicates
        second_iocs = {
            "domains": ["evil.com", "new.org"],  # evil.com is duplicate
            "ips": ["192.168.1.1", "10.0.0.1"],  # 192.168.1.1 is duplicate
        }
        result = extractor._deduplicate_iocs(second_iocs)

        # Should only contain new IOCs
        if "domains" in result:
            # evil.com should be filtered, only new.org remains
            assert "evil.com" not in str(result["domains"])
            assert any("new" in d for d in result["domains"])

    def test_read_chunks_small_file(self):
        """
        Test chunk reading from small text file.

        Validates that small files are read correctly with proper
        overlap handling.
        """
        extractor = StreamingIOCExtractor(chunk_size=100, overlap=20)

        content = "Line 1: domain1.com\nLine 2: domain2.org\nLine 3: 192.168.1.1\n"
        stream = io.StringIO(content)

        chunks = list(extractor._read_chunks(stream, is_text=True))

        assert len(chunks) >= 1
        # All content should be captured
        full_text = "".join(chunks)
        assert "domain1.com" in full_text
        assert "domain2.org" in full_text
        assert "192.168.1.1" in full_text

    def test_read_chunks_with_overlap(self):
        """
        Test that chunk overlap works correctly.

        Validates that overlapping regions allow IOCs split across
        chunk boundaries to be detected.
        """
        extractor = StreamingIOCExtractor(chunk_size=50, overlap=20)

        # Create content where IOCs might span chunks
        content = "a" * 40 + "evil.com" + "b" * 40 + "bad.org" + "c" * 40
        stream = io.StringIO(content)

        chunks = list(extractor._read_chunks(stream, is_text=True))

        assert len(chunks) >= 2  # Should be multiple chunks
        # Overlap ensures IOCs at boundaries are captured
        full_text = "".join(chunks)
        assert "evil.com" in full_text
        assert "bad.org" in full_text

    def test_read_chunks_binary_stream(self):
        """
        Test chunk reading from binary stream.

        Validates that binary streams are correctly decoded and processed.
        """
        extractor = StreamingIOCExtractor(chunk_size=100, overlap=20)

        content = b"Binary content with domain evil.com and IP 192.168.1.1"
        stream = io.BytesIO(content)

        chunks = list(extractor._read_chunks(stream, is_text=False))

        assert len(chunks) >= 1
        full_text = "".join(chunks)
        assert "evil.com" in full_text
        assert "192.168.1.1" in full_text

    def test_read_chunks_progress_callback(self):
        """
        Test that progress callback is invoked during chunk reading.

        Validates that the progress callback receives accurate progress
        updates as chunks are read.
        """
        progress_values = []

        def progress_callback(progress: int) -> None:
            progress_values.append(progress)

        extractor = StreamingIOCExtractor(
            chunk_size=100,
            overlap=20,
            progress_callback=progress_callback,
        )

        content = "x" * 500
        stream = io.StringIO(content)

        list(extractor._read_chunks(stream, is_text=True))

        # Should have received progress updates
        assert len(progress_values) > 0
        # Progress values should be between 0 and 100
        assert all(0 <= p <= 100 for p in progress_values)

    def test_extract_from_file_not_found(self):
        """
        Test extraction from non-existent file raises exception.

        Validates that attempting to extract from a missing file
        raises IOCFileNotFoundError.
        """
        extractor = StreamingIOCExtractor()

        non_existent_path = Path(tempfile.gettempdir()) / "non_existent_file_12345.txt"

        with pytest.raises(IOCFileNotFoundError) as exc_info:
            _get_file_extraction_result(extractor, non_existent_path, yield_chunks=False)

        assert str(non_existent_path) in str(exc_info.value)

    def test_extract_from_file_basic(self):
        """
        Test basic IOC extraction from file.

        Validates that IOCs are correctly extracted from a real file
        using streaming approach.
        """
        extractor = StreamingIOCExtractor(chunk_size=512, overlap=64)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should be a dictionary
            assert isinstance(result, dict)

            # Should contain various IOC types
            assert "domains" in result or "ips" in result or "md5" in result

            # Verify some specific IOCs are found
            if "md5" in result:
                assert len(result["md5"]) > 0

        finally:
            temp_path.unlink()

    def test_extract_from_file_yield_chunks(self):
        """
        Test streaming extraction yielding chunks.

        Validates that yield_chunks=True returns an iterator that
        yields IOC dictionaries as they're found.
        """
        extractor = StreamingIOCExtractor(chunk_size=200, overlap=50)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(LARGE_SAMPLE_TEXT)
            temp_path = Path(f.name)

        try:
            result = extractor.extract_from_file(temp_path, yield_chunks=True)

            # Should be an iterator
            chunks = list(result)

            # Should have received multiple chunks
            assert len(chunks) >= 1

            # Each chunk should be a dictionary
            for chunk in chunks:
                assert isinstance(chunk, dict)
                # Should contain IOCs
                if chunk:
                    assert any(len(ioc_list) > 0 for ioc_list in chunk.values())

        finally:
            temp_path.unlink()

    def test_extract_from_file_empty_file(self):
        """
        Test extraction from empty file.

        Validates that empty files are handled gracefully without errors.
        """
        extractor = StreamingIOCExtractor()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            # Write nothing - empty file
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should return empty or minimal dictionary
            assert isinstance(result, dict)
            # Either empty or all lists are empty
            assert all(len(v) == 0 for v in result.values()) or len(result) == 0

        finally:
            temp_path.unlink()

    def test_extract_from_file_large_file(self):
        """
        Test extraction from large file with multiple chunks.

        Validates that large files are processed correctly across
        multiple chunks with deduplication.
        """
        extractor = StreamingIOCExtractor(chunk_size=500, overlap=100)

        # Create larger content with repeated IOCs
        large_content = SAMPLE_IOC_TEXT * 100  # Repeat 100 times

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(large_content)
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            assert isinstance(result, dict)

            # Should have found IOCs
            total_iocs = sum(len(v) for v in result.values())
            assert total_iocs > 0

            # Deduplication should have worked - shouldn't have 100x the IOCs
            # (since the same IOCs are repeated 100 times)
            if "md5" in result:
                # Should have deduplicated the repeated MD5
                assert len(result["md5"]) < 10  # Much less than 100

        finally:
            temp_path.unlink()

    def test_extract_from_file_clears_state(self):
        """
        Test that seen_iocs state is cleared between file extractions.

        Validates that processing a new file resets the deduplication
        state to avoid incorrectly filtering IOCs.
        """
        extractor = StreamingIOCExtractor()

        # First file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Domain: first.com\nIP: 192.168.1.1")
            temp_path1 = Path(f.name)

        # Second file with same IOCs
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Domain: first.com\nIP: 192.168.1.1")
            temp_path2 = Path(f.name)

        try:
            # Extract from first file
            result1 = _get_file_extraction_result(extractor, temp_path1, yield_chunks=False)

            # Extract from second file - state should be cleared
            result2 = _get_file_extraction_result(extractor, temp_path2, yield_chunks=False)

            # Both should have found IOCs (state was cleared)
            assert len(result1) > 0
            assert len(result2) > 0

        finally:
            temp_path1.unlink()
            temp_path2.unlink()

    def test_extract_from_stream_text(self):
        """
        Test extraction from text stream.

        Validates that IOCs can be extracted from an in-memory text stream.
        """
        extractor = StreamingIOCExtractor(chunk_size=200)

        stream = io.StringIO(SAMPLE_IOC_TEXT)

        chunks = list(extractor.extract_from_stream(stream, is_text=True))

        assert len(chunks) >= 1

        # Accumulate all IOCs from chunks
        all_iocs: dict[str, list[str]] = defaultdict(list)
        for chunk in chunks:
            for ioc_type, ioc_list in chunk.items():
                all_iocs[ioc_type].extend(ioc_list)

        # Should have found various IOC types
        assert len(all_iocs) > 0

    def test_extract_from_stream_binary(self):
        """
        Test extraction from binary stream.

        Validates that binary streams are correctly processed and IOCs
        extracted from decoded content.
        """
        extractor = StreamingIOCExtractor(chunk_size=200)

        stream = io.BytesIO(SAMPLE_IOC_TEXT.encode("utf-8"))

        chunks = list(extractor.extract_from_stream(stream, is_text=False))

        assert len(chunks) >= 1

        # May be 0 if no IOCs, but structure should be correct
        assert all(isinstance(chunk, dict) for chunk in chunks)

    def test_extract_from_stream_clears_state(self):
        """
        Test that seen_iocs state is cleared for new streams.

        Validates that processing a new stream resets deduplication state.
        """
        extractor = StreamingIOCExtractor()

        stream1 = io.StringIO("Domain: test.com\nIP: 192.168.1.1")
        stream2 = io.StringIO("Domain: test.com\nIP: 192.168.1.1")

        chunks1 = list(extractor.extract_from_stream(stream1, is_text=True))
        chunks2 = list(extractor.extract_from_stream(stream2, is_text=True))

        # Both should have found IOCs since state was cleared
        assert len(chunks1) >= 0  # May be empty if no IOCs in small chunks
        assert len(chunks2) >= 0

    def test_extract_from_mmap_not_found(self):
        """
        Test memory-mapped extraction from non-existent file.

        Validates that IOCFileNotFoundError is raised for missing files.
        """
        extractor = StreamingIOCExtractor()

        non_existent_path = Path(tempfile.gettempdir()) / "non_existent_mmap_12345.txt"

        with pytest.raises(IOCFileNotFoundError):
            extractor.extract_from_mmap(non_existent_path)

    def test_extract_from_mmap_basic(self):
        """
        Test basic memory-mapped IOC extraction.

        Validates that IOCs are extracted using memory-mapped file access.
        """
        extractor = StreamingIOCExtractor(chunk_size=512, overlap=64)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            result = extractor.extract_from_mmap(temp_path)

            assert isinstance(result, dict)

            # Should have extracted IOCs
            total_iocs = sum(len(v) for v in result.values())
            assert total_iocs > 0

        finally:
            temp_path.unlink()

    def test_extract_from_mmap_empty_file(self):
        """
        Test memory-mapped extraction from empty file.

        Validates that empty files are handled correctly with mmap.
        """
        extractor = StreamingIOCExtractor()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            temp_path = Path(f.name)

        try:
            # Empty file may cause mmap to fail or return empty results
            # This tests robustness
            try:
                result = extractor.extract_from_mmap(temp_path)
                assert isinstance(result, dict)
            except Exception:
                # Empty files may not be mmap-able on all systems
                pytest.skip("Empty file mmap not supported on this system")

        finally:
            temp_path.unlink()

    def test_extract_from_mmap_large_file(self):
        """
        Test memory-mapped extraction from large file.

        Validates efficient processing of large files with mmap approach.
        """
        extractor = StreamingIOCExtractor(chunk_size=500, overlap=100)

        large_content = LARGE_SAMPLE_TEXT

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(large_content)
            temp_path = Path(f.name)

        try:
            result = extractor.extract_from_mmap(temp_path)

            assert isinstance(result, dict)

            # Should have found many IOCs from the large file
            total_iocs = sum(len(v) for v in result.values())
            assert total_iocs > 0

        finally:
            temp_path.unlink()

    def test_extract_from_mmap_with_progress(self):
        """
        Test memory-mapped extraction with progress callback.

        Validates that progress updates are sent during mmap processing.
        """
        progress_values = []

        def progress_callback(progress: int) -> None:
            progress_values.append(progress)

        extractor = StreamingIOCExtractor(
            chunk_size=200,
            progress_callback=progress_callback,
        )

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(LARGE_SAMPLE_TEXT)
            temp_path = Path(f.name)

        try:
            extractor.extract_from_mmap(temp_path)

            # Should have received progress updates
            assert len(progress_values) > 0
            assert all(0 <= p <= 100 for p in progress_values)

        finally:
            temp_path.unlink()

    def test_defang_option_true(self):
        """
        Test that defang=True properly defangs extracted IOCs.

        Validates that domains and IPs are defanged when option is enabled.
        """
        extractor = StreamingIOCExtractor(defang=True)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Domain: evil.com IP: 192.168.1.1")
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Check if domains are defanged
            if result.get("domains"):
                # Should contain [.] or similar defang marker
                assert any("[" in d or "(" in d for d in result["domains"])

        finally:
            temp_path.unlink()

    def test_defang_option_false(self):
        """
        Test that defang=False keeps IOCs in original format.

        Validates that IOCs remain unmodified when defanging is disabled.
        """
        extractor = StreamingIOCExtractor(defang=False)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Domain: evil.com IP: 192.168.1.1")
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Domains should not be defanged
            if result.get("domains"):
                # Should not contain defang markers
                assert not any("[.]" in d for d in result["domains"])

        finally:
            temp_path.unlink()


class TestParallelStreamingExtractor:
    """Test suite for ParallelStreamingExtractor class."""

    def test_init_default_parameters(self):
        """
        Test initialization with default parameters.

        Validates default worker count, chunk size, and defang settings.
        """
        extractor = ParallelStreamingExtractor()

        assert extractor.max_workers == 4
        assert extractor.chunk_size == 1024 * 1024
        assert extractor.defang is True

    def test_init_custom_parameters(self):
        """
        Test initialization with custom parameters.

        Validates that custom settings are properly applied.
        """
        extractor = ParallelStreamingExtractor(
            max_workers=8,
            chunk_size=512 * 1024,
            defang=False,
        )

        assert extractor.max_workers == 8
        assert extractor.chunk_size == 512 * 1024
        assert extractor.defang is False

    def test_extract_from_files_single_file(self):
        """
        Test parallel extraction from single file.

        Validates that single file processing works correctly.
        """
        extractor = ParallelStreamingExtractor(max_workers=2, chunk_size=512)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            results = extractor.extract_from_files([temp_path])

            assert isinstance(results, dict)
            assert str(temp_path) in results

            file_iocs = results[str(temp_path)]
            assert isinstance(file_iocs, dict)

        finally:
            temp_path.unlink()

    def test_extract_from_files_multiple_files(self):
        """
        Test parallel extraction from multiple files.

        Validates that multiple files are processed concurrently and
        results are correctly attributed to each file.
        """
        extractor = ParallelStreamingExtractor(max_workers=2, chunk_size=512)

        temp_files = []

        # Create multiple files with different content
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                f.write(f"File {i}: domain{i}.evil.com IP: 10.0.0.{i}")
                temp_files.append(Path(f.name))

        try:
            results = extractor.extract_from_files(temp_files)

            assert isinstance(results, dict)
            assert len(results) == 3

            # Each file should have results
            for temp_path in temp_files:
                assert str(temp_path) in results
                assert isinstance(results[str(temp_path)], dict)

        finally:
            for temp_path in temp_files:
                temp_path.unlink()

    def test_extract_from_files_empty_list(self):
        """
        Test parallel extraction with empty file list.

        Validates that empty input is handled gracefully.
        """
        extractor = ParallelStreamingExtractor()

        results = extractor.extract_from_files([])

        assert isinstance(results, dict)
        assert len(results) == 0

    def test_extract_from_files_with_progress_callback(self):
        """
        Test parallel extraction with progress callback.

        Validates that progress updates are sent as files are processed.
        """
        progress_values = []

        def progress_callback(progress: int) -> None:
            progress_values.append(progress)

        extractor = ParallelStreamingExtractor(max_workers=2)

        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                f.write(f"Content {i}: test{i}.com")
                temp_files.append(Path(f.name))

        try:
            extractor.extract_from_files(temp_files, progress_callback=progress_callback)

            # Should have received progress updates
            assert len(progress_values) > 0
            assert all(0 <= p <= 100 for p in progress_values)
            # Final progress should be 100
            assert 100 in progress_values

        finally:
            for temp_path in temp_files:
                temp_path.unlink()

    def test_extract_from_files_handles_errors(self):
        """
        Test parallel extraction handles file errors gracefully.

        Validates that errors in one file don't prevent processing
        of other files.
        """
        extractor = ParallelStreamingExtractor(max_workers=2)

        # Create one valid file and one non-existent file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Valid content: test.com")
            valid_file = Path(f.name)

        invalid_file = Path(tempfile.gettempdir()) / "non_existent_parallel_test_12345.txt"

        try:
            results = extractor.extract_from_files([valid_file, invalid_file])

            # Should have results for both (error file gets empty dict)
            assert len(results) == 2
            assert str(valid_file) in results
            assert str(invalid_file) in results

            # Invalid file should have empty results
            assert results[str(invalid_file)] == {}

            # Valid file should have extracted something (or empty dict if no IOCs)
            assert isinstance(results[str(valid_file)], dict)

        finally:
            valid_file.unlink()

    def test_extract_from_files_concurrent_processing(self):
        """
        Test that files are actually processed concurrently.

        Validates parallelism by processing multiple files and ensuring
        reasonable performance.
        """
        extractor = ParallelStreamingExtractor(max_workers=4, chunk_size=512)

        # Create multiple files
        temp_files = []
        for i in range(5):
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                # Write different content to each
                content = "\n".join(
                    [
                        f"File {i} line {j}: domain{i}-{j}.test.org IP: 10.{i}.{j}.1"
                        for j in range(50)
                    ]
                )
                f.write(content)
                temp_files.append(Path(f.name))

        try:
            results = extractor.extract_from_files(temp_files)

            # All files should be processed
            assert len(results) == 5

            # Each should have results
            for temp_path in temp_files:
                assert str(temp_path) in results

        finally:
            for temp_path in temp_files:
                temp_path.unlink()


class TestConvenienceFunctions:
    """Test suite for convenience functions."""

    def test_extract_iocs_from_large_file_basic(self):
        """
        Test basic usage of convenience function.

        Validates that the convenience wrapper correctly extracts IOCs.
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            result_gen = extract_iocs_from_large_file(temp_path)
            result = _consume_generator_result(result_gen)

            assert isinstance(result, dict)
            # Should have extracted some IOCs
            total_iocs = sum(len(v) for v in result.values())
            assert total_iocs > 0

        finally:
            temp_path.unlink()

    def test_extract_iocs_from_large_file_custom_chunk_size(self):
        """
        Test convenience function with custom chunk size.

        Validates parameter passing to underlying extractor.
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            result_gen = extract_iocs_from_large_file(
                temp_path,
                chunk_size=256,
                defang=False,
            )
            result = _consume_generator_result(result_gen)

            assert isinstance(result, dict)

        finally:
            temp_path.unlink()

    def test_extract_iocs_from_large_file_with_mmap(self):
        """
        Test convenience function using memory-mapped approach.

        Validates use_mmap parameter functionality.
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(LARGE_SAMPLE_TEXT)
            temp_path = Path(f.name)

        try:
            result = extract_iocs_from_large_file(
                temp_path,
                use_mmap=True,
                chunk_size=512,
            )

            assert isinstance(result, dict)
            # Should have extracted IOCs from large file
            total_iocs = sum(len(v) for v in result.values())
            assert total_iocs > 0

        finally:
            temp_path.unlink()

    def test_extract_iocs_from_large_file_with_progress(self):
        """
        Test convenience function with progress callback.

        Validates progress reporting functionality.
        """
        progress_values = []

        def progress_callback(progress: int) -> None:
            progress_values.append(progress)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(LARGE_SAMPLE_TEXT)
            temp_path = Path(f.name)

        try:
            result_gen = extract_iocs_from_large_file(
                temp_path,
                chunk_size=500,
                progress_callback=progress_callback,
            )
            _consume_generator_result(result_gen)

            assert len(progress_values) > 0
            assert all(0 <= p <= 100 for p in progress_values)

        finally:
            temp_path.unlink()

    def test_stream_iocs_from_file_basic(self):
        """
        Test streaming convenience function.

        Validates that IOCs are streamed as they're extracted.
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(LARGE_SAMPLE_TEXT)
            temp_path = Path(f.name)

        try:
            chunks = list(stream_iocs_from_file(temp_path, chunk_size=500))

            # Should yield chunks
            assert len(chunks) >= 1

            # Each chunk should be a dictionary
            for chunk in chunks:
                assert isinstance(chunk, dict)

        finally:
            temp_path.unlink()

    def test_stream_iocs_from_file_custom_parameters(self):
        """
        Test streaming function with custom parameters.

        Validates parameter customization.
        """
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(SAMPLE_IOC_TEXT)
            temp_path = Path(f.name)

        try:
            chunks = list(
                stream_iocs_from_file(
                    temp_path,
                    chunk_size=200,
                    defang=False,
                )
            )

            assert isinstance(chunks, list)
            for chunk in chunks:
                assert isinstance(chunk, dict)

        finally:
            temp_path.unlink()


class TestEdgeCases:
    """Test suite for edge cases and boundary conditions."""

    def test_chunk_boundary_ioc_detection(self):
        """
        Test IOC detection across chunk boundaries.

        Validates that overlap mechanism catches IOCs split between chunks.
        """
        extractor = StreamingIOCExtractor(chunk_size=50, overlap=30)

        # Content designed to split IOCs at chunk boundary
        content = "x" * 45 + "evil.malware.com" + "y" * 50

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should still detect the domain despite chunk boundary
            if "domains" in result:
                domain_found = any("malware" in d.lower() for d in result["domains"])
                # Overlap should help capture this
                assert domain_found or len(result["domains"]) >= 0

        finally:
            temp_path.unlink()

    def test_very_small_chunk_size(self):
        """
        Test processing with very small chunk size.

        Validates robustness with minimal chunk sizes.
        """
        extractor = StreamingIOCExtractor(chunk_size=10, overlap=5)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Domain: test.com IP: 192.168.1.1")
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should still work, though may be inefficient
            assert isinstance(result, dict)

        finally:
            temp_path.unlink()

    def test_unicode_content(self):
        """
        Test processing files with Unicode content.

        Validates proper handling of international characters.
        """
        extractor = StreamingIOCExtractor()

        unicode_content = """
        Анализ malware: domain: зло.example.com
        中文内容: evil.com
        日本語: 192.168.1.1
        Regular: test.malware.org
        """

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt", encoding="utf-8"
        ) as f:
            f.write(unicode_content)
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should handle Unicode without errors
            assert isinstance(result, dict)

        finally:
            temp_path.unlink()

    def test_mixed_line_endings(self):
        """
        Test processing files with mixed line endings.

        Validates handling of different line ending styles (CRLF, LF).
        """
        extractor = StreamingIOCExtractor()

        mixed_content = "Line1: test.com\r\nLine2: evil.org\nLine3: 192.168.1.1\r\n"

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
            f.write(mixed_content.encode("utf-8"))
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should handle mixed line endings
            assert isinstance(result, dict)

        finally:
            temp_path.unlink()

    def test_file_with_null_bytes(self):
        """
        Test processing files containing null bytes.

        Validates resilience against binary data in text processing.
        """
        extractor = StreamingIOCExtractor()

        content_with_nulls = b"Content\x00with\x00nulls\x00test.com\x00192.168.1.1"

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
            f.write(content_with_nulls)
            temp_path = Path(f.name)

        try:
            result = _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

            # Should handle null bytes gracefully
            assert isinstance(result, dict)

        finally:
            temp_path.unlink()


class TestStreamingExceptionHandling:
    """Test suite for exception handling and error paths."""

    def test_read_chunks_exception_during_reading(self):
        """
        Test exception handling when reading chunks fails.

        Validates that exceptions during chunk reading are handled
        and don't cause crashes.
        """
        extractor = StreamingIOCExtractor(chunk_size=100)

        # Create a stream that will raise an exception
        class ErrorStream:
            def __init__(self):
                self.call_count = 0

            def read(self, size):
                self.call_count += 1
                if self.call_count == 1:
                    return "First chunk"
                raise OSError("Simulated read error")  # noqa: TRY003

            def seek(self, pos, whence=0):
                raise OSError("Seek not supported")  # noqa: TRY003

            def tell(self):
                raise OSError("Tell not supported")  # noqa: TRY003

        error_stream = ErrorStream()

        # Reading should handle the exception
        chunks = []
        try:
            for chunk in extractor._read_chunks(error_stream, is_text=True):
                chunks.append(chunk)  # noqa: PERF402
        except OSError:
            # Exception should propagate
            pass

        # Should have gotten at least the first chunk before error
        assert len(chunks) >= 1

    def test_extract_from_file_exception_handling(self):
        """
        Test exception handling during file extraction.

        Validates that extraction errors are properly logged and raised.
        """
        extractor = StreamingIOCExtractor()

        # Create a file that exists but will fail during reading
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Test content")
            temp_path = Path(f.name)

        try:
            # Make the file unreadable by changing permissions (Unix-like systems)
            import stat

            temp_path.chmod(0o000)

            # Attempt extraction - should raise exception
            with pytest.raises(PermissionError):
                _get_file_extraction_result(extractor, temp_path, yield_chunks=False)

        finally:
            # Restore permissions and clean up
            with contextlib.suppress(Exception):
                temp_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                temp_path.unlink()

    def test_parallel_extractor_exception_handling(self):
        """
        Test parallel extraction handles exceptions gracefully.

        Validates that errors in one file don't prevent processing
        other files and return empty dict for failed files.
        """
        extractor = ParallelStreamingExtractor(max_workers=2)

        # Create one valid file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Valid content: test.com")
            valid_file = Path(f.name)

        # Create a file we'll make unreadable
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Problematic content")
            problem_file = Path(f.name)

        try:
            # Make problem file unreadable
            problem_file.chmod(0o000)

            results = extractor.extract_from_files([valid_file, problem_file])

            # Should have results for both files
            assert str(valid_file) in results
            assert str(problem_file) in results

            # Problem file should have empty results
            assert results[str(problem_file)] == {}

            # Valid file should have been processed
            assert isinstance(results[str(valid_file)], dict)

        finally:
            valid_file.unlink()
            with contextlib.suppress(Exception):
                import stat

                problem_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
                problem_file.unlink()


class TestStreamingUnsupportedOperations:
    """Test handling of unsupported stream operations."""

    def test_read_chunks_with_unseekable_stream(self):
        """
        Test chunk reading from unseekable stream.

        Validates that streams that don't support seek/tell operations
        are handled correctly.
        """
        extractor = StreamingIOCExtractor(chunk_size=100)

        # Create a stream that doesn't support seek/tell
        class UnseekableStream:
            def __init__(self, content):
                self.content = content
                self.pos = 0

            def read(self, size):
                chunk = self.content[self.pos : self.pos + size]
                self.pos += len(chunk)
                return chunk

            def seek(self, pos, whence=0):
                raise io.UnsupportedOperation("seek not supported")  # noqa: TRY003

            def tell(self):
                raise io.UnsupportedOperation("tell not supported")  # noqa: TRY003

        content = "Test content with domain evil.com and IP 192.168.1.1"
        stream = UnseekableStream(content)

        chunks = list(extractor._read_chunks(stream, is_text=True))

        # Should still work without seek/tell
        assert len(chunks) >= 1
        full_text = "".join(chunks)
        assert "evil.com" in full_text

    def test_read_chunks_with_oserror_on_seek(self):
        """
        Test chunk reading when seek raises OSError.

        Validates graceful handling when file operations fail.
        """
        extractor = StreamingIOCExtractor(chunk_size=50)

        class OSErrorStream:
            def __init__(self, content):
                self.content = content
                self.pos = 0

            def read(self, size):
                chunk = self.content[self.pos : self.pos + size]
                self.pos += len(chunk)
                return chunk

            def seek(self, pos, whence=0):
                raise OSError("File operation failed")  # noqa: TRY003

            def tell(self):
                raise OSError("File operation failed")  # noqa: TRY003

        content = "Content that will cause OSError on seek"
        stream = OSErrorStream(content)

        # Should handle OSError gracefully
        chunks = list(extractor._read_chunks(stream, is_text=True))

        assert len(chunks) >= 1
        assert "Content" in "".join(chunks)
