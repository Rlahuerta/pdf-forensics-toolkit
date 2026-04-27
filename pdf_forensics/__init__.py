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

# Re-export detection, scoring, and reporting functions
from pdf_forensics.detection import (
    _detect_incremental_updates,
    _detect_tampering_indicators,
    _detect_security_indicators,
    _compare_library_metadata,
)
from pdf_forensics.scoring import (
    _quantify_changes,
    _calculate_integrity_score,
    _calculate_similarity,
)
from pdf_forensics.reporting import generate_source_report
from pdf_forensics.signature import validate_signature
from pdf_forensics.pdf_document import PDFDocument
from pdf_forensics.limits import check_file_size, validate_pdf_file

# Lazy import for top-level script functions (circular dependency with pdf_source_identifier)
def __getattr__(name):
    if name in ("extract_source_fingerprint", "analyze_source_similarity"):
        import pdf_source_identifier
        return getattr(pdf_source_identifier, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "extract_source_fingerprint",
    "analyze_source_similarity",
    "generate_source_report",
    "validate_signature",
    "PDFDocument",
    "check_file_size",
    "validate_pdf_file",
    "KNOWN_PRODUCERS",
    "SUSPICIOUS_PRODUCERS",
    "COMMON_PRODUCERS",
    "__version__",
]
