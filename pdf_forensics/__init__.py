"""
PDF Forensics Toolkit

A comprehensive forensic toolkit for analyzing PDF documents to detect tampering,
identify document origins, and assess authenticity.
"""

__version__ = "1.0.0"

# Re-export constants from pdf_forensics.constants
from pdf_forensics.constants import (
    KNOWN_PRODUCERS,
    SUSPICIOUS_PRODUCERS,
    COMMON_PRODUCERS,
)

# Re-export public API from pdf_source_identifier
# NOTE: These imports are temporary until Wave 3 module extraction is complete
# Using lazy import via __getattr__ to avoid circular dependency since
# pdf_source_identifier imports from pdf_forensics.constants
def __getattr__(name):
    if name in ("extract_source_fingerprint", "analyze_source_similarity", "generate_source_report"):
        import pdf_source_identifier
        return getattr(pdf_source_identifier, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "extract_source_fingerprint",
    "analyze_source_similarity", 
    "generate_source_report",
    "KNOWN_PRODUCERS",
    "SUSPICIOUS_PRODUCERS",
    "COMMON_PRODUCERS",
    "__version__",
]
