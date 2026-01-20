#!/usr/bin/env python3

"""
Hash extraction mixin for IOC extraction.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from iocparser.modules.extractor_base import ExtractorBase


class HashExtractionMixin(ExtractorBase):
    """Hash extraction methods."""

    def extract_md5(self, text: str) -> list[str]:
        """Extract MD5 hashes from text."""
        return self._extract_hash(text, "md5")

    def extract_sha1(self, text: str) -> list[str]:
        """Extract SHA1 hashes from text."""
        return self._extract_hash(text, "sha1")

    def extract_sha256(self, text: str) -> list[str]:
        """Extract SHA256 hashes from text."""
        return self._extract_hash(text, "sha256")

    def extract_sha512(self, text: str) -> list[str]:
        """Extract SHA512 hashes from text."""
        return self._extract_hash(text, "sha512")

    def extract_ssdeep(self, text: str) -> list[str]:
        """Extract ssdeep hashes from text."""
        return self._extract_pattern(text, "ssdeep")
