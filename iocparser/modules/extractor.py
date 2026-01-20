#!/usr/bin/env python3

"""
Enhanced module for extracting indicators of compromise (IOCs) from text.
Includes additional IOC types and improved extraction methods.

Author: Marc Rivero | @seifreed
"""

from __future__ import annotations

from iocparser.modules.extractor_aggregate import ExtractionAggregateMixin
from iocparser.modules.extractor_artifacts import ArtifactExtractionMixin
from iocparser.modules.extractor_hashes import HashExtractionMixin
from iocparser.modules.extractor_network import NetworkExtractionMixin


class IOCExtractor(
    HashExtractionMixin,
    NetworkExtractionMixin,
    ArtifactExtractionMixin,
    ExtractionAggregateMixin,
):
    """Enhanced class for extracting different types of IOCs from text."""
