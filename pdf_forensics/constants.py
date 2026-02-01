"""
PDF Forensics Toolkit - Constants Module

Centralized storage of known producers, suspicious online tools, and common legitimate producers.
"""

from typing import Final, Dict, List, Any

# Map of known PDF producers to their metadata
# Used to identify the software system that created a PDF
KNOWN_PRODUCERS: Final[Dict[str, Dict[str, str]]] = {
    "pdfsharp": {"system": "PDFsharp (.NET)", "type": "dynamic_generation", "platform": ".NET/C#"},
    "itext": {"system": "iText", "type": "dynamic_generation", "platform": "Java"},
    "reportlab": {"system": "ReportLab", "type": "dynamic_generation", "platform": "Python"},
    "fpdf": {"system": "FPDF", "type": "dynamic_generation", "platform": "PHP"},
    "tcpdf": {"system": "TCPDF", "type": "dynamic_generation", "platform": "PHP"},
    "wkhtmltopdf": {"system": "wkhtmltopdf", "type": "html_to_pdf", "platform": "WebKit"},
    "weasyprint": {"system": "WeasyPrint", "type": "html_to_pdf", "platform": "Python"},
    "puppeteer": {"system": "Puppeteer/Chrome", "type": "html_to_pdf", "platform": "Node.js"},
    "prince": {"system": "Prince XML", "type": "html_to_pdf", "platform": "C++"},
    "adobe acrobat": {"system": "Adobe Acrobat", "type": "desktop_creation", "platform": "Desktop"},
    "adobe experience manager": {"system": "Adobe Experience Manager Forms", "type": "enterprise_forms", "platform": "Java/Enterprise"},
    "designer": {"system": "Adobe LiveCycle Designer", "type": "enterprise_forms", "platform": "Enterprise"},
    "microsoft": {"system": "Microsoft Office", "type": "office_export", "platform": "Desktop"},
    "libreoffice": {"system": "LibreOffice", "type": "office_export", "platform": "Desktop"},
    "openoffice": {"system": "OpenOffice", "type": "office_export", "platform": "Desktop"},
    "chrome": {"system": "Chrome Print", "type": "browser_print", "platform": "Browser"},
    "firefox": {"system": "Firefox Print", "type": "browser_print", "platform": "Browser"},
    "safari": {"system": "Safari Print", "type": "browser_print", "platform": "Browser"},
    "quartz": {"system": "macOS Quartz", "type": "os_native", "platform": "macOS"},
    "cairo": {"system": "Cairo Graphics", "type": "dynamic_generation", "platform": "C/Multi"},
    "ghostscript": {"system": "Ghostscript", "type": "conversion", "platform": "PostScript"},
    "pdftk": {"system": "PDFtk", "type": "manipulation", "platform": "CLI"},
    "qpdf": {"system": "QPDF", "type": "manipulation", "platform": "CLI"},
}

# List of online PDF editors/generators that may indicate manipulation
# These are higher-risk producers because they have lower integrity controls
SUSPICIOUS_PRODUCERS: Final[List[str]] = [
    "ilovepdf", "smallpdf", "pdf24", "sejda", "pdfcandy",
    "online2pdf", "sodapdf", "pdf2go", "cleverpdf"
]

# List of common legitimate producers that don't add risk to integrity score
# These are widely used, reputable tools with strong integrity controls
COMMON_PRODUCERS: Final[List[str]] = [
    "microsoft print to pdf", "chrome", "firefox"
]

# ============================================================================
# FORENSIC ANALYSIS NUMERIC THRESHOLDS
# ============================================================================

# Content Structure Thresholds - detect suspicious document structures
MAX_CONTENT_STREAMS_PER_PAGE: Final[int] = 10
"""Maximum normal content streams per page. More than this may indicate shadow attacks."""

MAX_ORPHAN_OBJECTS_NORMAL: Final[int] = 10
"""Maximum normal orphan objects. More suggests potential hidden content."""

MAX_FORM_FIELDS_NORMAL: Final[int] = 10
"""Maximum normal form fields. More than this may indicate suspicious manipulation."""

MAX_ANNOTATIONS_NORMAL: Final[int] = 10
"""Maximum normal annotations. Excessive annotations added after creation."""

# Scanning and Limits - prevent resource exhaustion
MAX_DIFF_LINES_TO_REPORT: Final[int] = 50
"""Limit diff output to first N lines to keep reports manageable."""

MAX_DIFF_LINES_PREVIEW: Final[int] = 30
"""Limit preview diff lines in similarity analysis reports."""

# Integrity Score Thresholds - interpret document trustworthiness
INTEGRITY_SCORE_EXCELLENT_MIN: Final[int] = 90
"""Minimum score for 'Excellent' integrity rating (90-100)."""

INTEGRITY_SCORE_GOOD_MIN: Final[int] = 70
"""Minimum score for 'Good' integrity rating (70-89)."""

INTEGRITY_SCORE_QUESTIONABLE_MIN: Final[int] = 50
"""Minimum score for 'Questionable' integrity rating (50-69)."""

# Tampering Risk Thresholds - interpret modification risk
TAMPERING_RISK_CRITICAL_MIN: Final[int] = 60
"""Minimum score for 'Critical' tampering risk (61-100)."""

TAMPERING_RISK_HIGH_MIN: Final[int] = 40
"""Minimum score for 'High' tampering risk (41-60)."""

TAMPERING_RISK_MEDIUM_MIN: Final[int] = 20
"""Minimum score for 'Medium' tampering risk (21-40)."""

# Similarity Score Thresholds - grouping documents by source
SIMILARITY_SCORE_EXCELLENT_MIN: Final[int] = 80
"""Minimum score for documents from the same source (likely same pipeline)."""

SIMILARITY_SCORE_GOOD_MIN: Final[int] = 50
"""Minimum score for similar documents (possibly related sources)."""

# Scoring Point Values - contributions to integrity and modification scores
SCORING_POINTS_SUBSTANTIAL_CHANGE: Final[int] = 15
"""Points deducted for substantial changes to document."""

SCORING_POINTS_ID_MISMATCH: Final[int] = 20
"""Points added for document ID mismatch (indicates modification)."""

SCORING_POINTS_DATE_MISMATCH: Final[int] = 10
"""Points added for creation/modification date mismatch."""

SCORING_POINTS_LARGE_SIZE_INCREASE: Final[int] = 20
"""Points added for large size increase (>50%) in updates."""

SCORING_POINTS_MEDIUM_SIZE_INCREASE: Final[int] = 15
"""Points added for medium size increase (20-50%) in updates."""

SCORING_POINTS_SMALL_SIZE_INCREASE: Final[int] = 10
"""Points added for small size increase (5-20%) in updates."""

SCORING_POINTS_ORPHAN_OBJECTS: Final[int] = 15
"""Points added for presence of orphan objects."""

SCORING_POINTS_HIDDEN_CONTENT: Final[int] = 25
"""Points added for hidden content indicators."""

SCORING_POINTS_SECURITY_THREAT: Final[int] = 10
"""Points added per security threat (JavaScript, launch actions, etc.)."""

# Percentage Thresholds - relative change indicators
SIZE_INCREASE_LARGE_PERCENT: Final[int] = 50
"""Threshold for 'large' size increase (>50%)."""

SIZE_INCREASE_MEDIUM_PERCENT: Final[int] = 20
"""Threshold for 'medium' size increase (20-50%)."""

SIZE_INCREASE_SMALL_PERCENT: Final[int] = 5
"""Threshold for 'small' size increase (5-20%)."""

# Object Scanning Limits - balance thoroughness vs performance
MAX_OBJECTS_TO_ANALYZE: Final[int] = 1000
"""Maximum PDF objects to analyze (prevent resource exhaustion on malicious PDFs)."""

# Score Bounds - all scores capped at these values
MAX_SCORE: Final[int] = 100
"""Maximum value for any integrity, tampering, or similarity score."""

MIN_SCORE: Final[int] = 0
"""Minimum value for any integrity, tampering, or similarity score."""
