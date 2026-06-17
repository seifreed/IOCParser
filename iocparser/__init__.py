"""
IOCParser - A tool for extracting Indicators of Compromise from security reports

Author: Marc Rivero | @seifreed
"""

import iocparser.api_extraction as extraction
import iocparser.api_persistence as persistence
import iocparser.api_pipeline as pipeline
import iocparser.plugins as integrations
from iocparser import renderers
from iocparser._version import resolve_version

__version__ = resolve_version()
__all__ = [
    "extraction",
    "integrations",
    "persistence",
    "pipeline",
    "renderers",
]
