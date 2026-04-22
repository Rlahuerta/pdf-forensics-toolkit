# PDF Forensics Toolkit

A comprehensive forensic toolkit for analyzing PDF documents to detect tampering, identify document origins, and assess authenticity.

## Installation

```bash
pip install pdf-forensics-toolkit
```

Or install from source:

```bash
git clone https://github.com/Rlahuerta/pdf-forensics-toolkit.git
cd pdf-forensics-toolkit
pip install -e .
```

**Requirements:** Python 3.11+

### Dependencies

The toolkit uses multiple PDF libraries for cross-validated analysis:

| Library | Purpose |
|---------|---------|
| PyMuPDF (fitz) | Text extraction, page analysis, content hashing |
| pikepdf | Structural analysis, incremental update detection |
| pypdf | Metadata extraction, cross-library validation |
| pdfplumber | Supplementary text/content extraction |
| pyHanko | Digital signature validation |
| python-magic | File type detection |
| pdfid | PDF identifier analysis |
| peepdf-3 | Low-level PDF structure inspection |

---

## CLI Usage

The toolkit provides three commands, also accessible as subcommands:

### Analyze (default)

Identifies the source system of PDF documents and groups them by origin.

```bash
# Analyze one or more PDFs
pdf-forensics analyze document.pdf
pdf-forensics analyze file1.pdf file2.pdf file3.pdf
pdf-forensics analyze /path/to/pdf/directory/

# Custom output file and format
pdf-forensics analyze document.pdf --output report.md
pdf-forensics analyze document.pdf --format json

# Increase verbosity
pdf-forensics analyze document.pdf -v      # INFO level
pdf-forensics analyze document.pdf -vv     # DEBUG level
```

### Verify

Validates digital signatures in a PDF document.

```bash
pdf-forensics verify signed_document.pdf
pdf-forensics verify signed_document.pdf --output sig_report.md
pdf-forensics verify signed_document.pdf --format json
```

### Compare

Compares two PDF files and generates a forensic diff report.

```bash
pdf-forensics compare original.pdf modified.pdf
pdf-forensics compare original.pdf modified.pdf --output diff_report.md
pdf-forensics compare original.pdf modified.pdf --format json
```

### Global Options

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `-v` | INFO verbosity (log level) |
| `-vv` | DEBUG verbosity (log level) |
| `--format {markdown,json}` | Output format (default: markdown) |
| `--output PATH` | Custom output file path |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PDF_FORENSICS_LOG_LEVEL` | Set log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

### Running as a Module

```bash
python -m pdf_forensics analyze document.pdf
python -m pdf_forensics verify signed.pdf
python -m pdf_forensics compare a.pdf b.pdf
```

---

## Python API

### Source Identification

```python
from pdf_forensics import extract_source_fingerprint, analyze_source_similarity

# Extract a source fingerprint from a single PDF
fingerprint = extract_source_fingerprint("document.pdf")
print(fingerprint["source_hash"])           # Unique source identifier
print(fingerprint["source_id"]["system"])    # e.g. "Adobe Acrobat"
print(fingerprint["integrity_score"])        # 0-100 integrity score

# Compare multiple documents by source
fingerprints = [
    extract_source_fingerprint("doc1.pdf"),
    extract_source_fingerprint("doc2.pdf"),
    extract_source_fingerprint("doc3.pdf"),
]
similarity = analyze_source_similarity(fingerprints)
print(similarity["group_count"])   # Number of unique sources
print(similarity["similarities"])   # Pairwise similarity scores
```

### Detection Functions

```python
from pdf_forensics.detection import (
    _detect_incremental_updates,
    _detect_tampering_indicators,
    _detect_security_indicators,
)

# Detect incremental updates (modifications saved after original)
updates = _detect_incremental_updates("document.pdf")
if updates["has_incremental_updates"]:
    print(f"Document modified {updates['update_count']} time(s)")
    print(f"Original ID preserved: {updates['original_id_match']}")

# Detect tampering indicators
tampering = _detect_tampering_indicators("document.pdf")
print(f"Compromised: {tampering['is_compromised']}")
print(f"Risk score: {tampering['risk_score']}/100")
print(f"Shadow attack risk: {tampering['shadow_attack_risk']}")

# Detect security threats
security = _detect_security_indicators("document.pdf")
print(f"JavaScript: {security['has_javascript']}")
print(f"Launch actions: {security['has_launch_action']}")
print(f"Embedded files: {security['has_embedded_files']}")
```

### Scoring Functions

```python
from pdf_forensics.scoring import _calculate_integrity_score, _calculate_similarity
from pdf_forensics.constants import INTEGRITY_SCORE_EXCELLENT_MIN

score = _calculate_integrity_score(fingerprint)
if score >= INTEGRITY_SCORE_EXCELLENT_MIN:
    print("Document integrity is excellent")
else:
    print(f"Integrity score: {score}/100")

# Calculate similarity between two fingerprints (0-100)
sim_score = _calculate_similarity(fp1, fp2)
```

### Signature Validation

```python
from pdf_forensics.signature import validate_signature

result = validate_signature("signed_document.pdf")
if result["has_signatures"]:
    print(f"Valid: {result['signature_valid']}")
    print(f"Document intact: {result['intact']}")
else:
    print("No digital signatures found")
```

### Report Generation

```python
from pdf_forensics.reporting import generate_source_report, generate_signature_report

# Generate source analysis report
report_path = generate_source_report(fingerprints, similarity, "report.md")

# Generate signature report
sig_path = generate_signature_report(results, "signature_report.md")
```

### PDFDocument Context Manager

Open a PDF once and access it through multiple libraries without redundant file opens:

```python
from pdf_forensics import PDFDocument

with PDFDocument("document.pdf") as pdf:
    # Access via PyMuPDF (fitz)
    page_count = len(pdf.fitz_doc)
    text = pdf.fitz_doc[0].get_text()

    # Access via pikepdf
    metadata = pdf.pikepdf_doc.docinfo

    # Access via pypdf
    reader = pdf.pypdf_reader
    num_pages = len(reader.pages)
```

### File Validation

```python
from pdf_forensics import validate_pdf_file, check_file_size

# Full validation (size, symlink, PDF header)
is_ok, error = validate_pdf_file("document.pdf")
if not is_ok:
    print(f"Validation failed: {error}")

# Size-only check
is_ok, error = check_file_size("document.pdf")
```

---

## Constants Reference

All thresholds and scoring values are centralized in `pdf_forensics.constants` for tuning and consistency.

### Producer Identification

```python
from pdf_forensics.constants import KNOWN_PRODUCERS, SUSPICIOUS_PRODUCERS, COMMON_PRODUCERS

# Known producers with classification metadata
for key, meta in KNOWN_PRODUCERS.items():
    print(f"{key}: {meta['system']} ({meta['type']}, {meta['platform']})")

# Online editors that indicate potential manipulation
print(SUSPICIOUS_PRODUCERS)  # ["ilovepdf", "smallpdf", "pdf24", ...]

# Common legitimate producers (no risk penalty)
print(COMMON_PRODUCERS)      # ["microsoft print to pdf", "chrome", "firefox"]
```

### Scoring Thresholds

| Constant | Default | Purpose |
|----------|---------|---------|
| `INTEGRITY_SCORE_EXCELLENT_MIN` | 90 | Minimum score for "Excellent" rating |
| `INTEGRITY_SCORE_GOOD_MIN` | 70 | Minimum score for "Good" rating |
| `INTEGRITY_SCORE_QUESTIONABLE_MIN` | 50 | Minimum score for "Questionable" rating |
| `TAMPERING_RISK_CRITICAL_MIN` | 60 | Minimum score for "Critical" tampering risk |
| `TAMPERING_RISK_HIGH_MIN` | 40 | Minimum score for "High" tampering risk |
| `TAMPERING_RISK_MEDIUM_MIN` | 20 | Minimum score for "Medium" tampering risk |
| `SIMILARITY_SCORE_EXCELLENT_MIN` | 80 | Score indicating same source pipeline |
| `SIMILARITY_SCORE_GOOD_MIN` | 50 | Score indicating possibly related sources |

### Content Limits

| Constant | Default | Purpose |
|----------|---------|---------|
| `MAX_CONTENT_STREAMS_PER_PAGE` | 10 | Streams above this may indicate shadow attacks |
| `MAX_ORPHAN_OBJECTS_NORMAL` | 10 | Objects above this suggest hidden content |
| `MAX_FORM_XOBJECTS_PER_PAGE` | 10 | XObjects above this may indicate overlay content |
| `MAX_ANNOTATIONS_NORMAL` | 10 | Excessive annotations indicate post-creation edits |
| `MAX_OBJECTS_TO_ANALYZE` | 1000 | Object cap to prevent resource exhaustion |
| `MAX_OBJECTS_ORPHAN_SCAN` | 2000 | Extended scan cap for orphan detection |
| `MAX_SECURITY_SCAN_OBJECTS` | 1000 | Cap for security indicator scanning |
| `MAX_PAGES_TO_SCAN` | 20 | Page limit for content hashing |

### Entropy Analysis

| Constant | Default | Purpose |
|----------|---------|---------|
| `ENTROPY_HIGH_THRESHOLD` | 7.5 | Shannon entropy above this flags possible obfuscation |
| `HIGH_ENTROPY_RATIO` | 0.5 | Ratio of high-entropy streams above this is suspicious |
| `STREAM_ANALYSIS_SIZE_LIMIT` | 65536 | Max bytes to read per stream for entropy analysis |
| `MIN_STREAM_SIZE_BYTES` | 100 | Minimum stream size to include in entropy analysis |

---

## Result Types

All detection functions return TypedDict instances with well-defined schemas.

### IncrementalUpdateResult

```python
{
    "has_incremental_updates": bool,   # Whether updates were detected
    "update_count": int,               # Number of incremental updates
    "trailer_count": int,              # Number of trailer sections
    "xref_sections": int,              # Number of xref sections
    "suspicious": bool,                # Whether updates look suspicious
    "was_modified": bool,              # Whether document was modified
    "modification_indicators": list,   # List of modification indicators
    "original_id_match": bool,          # Whether original ID is preserved
    "dates_match": bool,               # Whether creation/mod dates match
    "creation_date": str,              # Document creation date
    "modification_date": str,          # Last modification date
    "details": list,                   # Human-readable details
}
```

### TamperingResult

```python
{
    "is_compromised": bool,                    # Whether tampering is likely
    "compromise_confidence": "none|low|medium|high",  # Confidence level
    "risk_score": int,                         # 0-100 risk score
    "indicators": list,                        # List of tampering indicators
    "structural_anomalies": list,              # Structural anomalies found
    "hidden_content": list,                    # Hidden content detected
    "orphan_objects": list,                    # Unreferenced objects found
    "metadata_inconsistencies": list,          # Metadata inconsistencies
    "page_hashes": list,                       # Per-page content hashes
    "shadow_attack_risk": bool,                # Whether shadow attack is possible
    "recommendations": list,                   # Recommended actions
}
```

### SecurityResult

```python
{
    "has_javascript": bool,          # JavaScript embedded in document
    "has_launch_action": bool,        # Launch actions that could execute programs
    "has_embedded_files": bool,       # Embedded file attachments
    "has_openaction": bool,           # Auto-execute actions on open
    "has_aa": bool,                   # Additional actions (AA) dictionary
    "urls_found": list,               # URLs found in the document
    "suspicious_elements": list,      # List of suspicious elements
    "risk_level": str,                # "low", "medium", or "high"
}
```

### QuantifyChangesResult

```python
{
    "modification_score": int,        # 0-100 modification severity score
    "bytes_added": int,              # Bytes added in updates
    "revision_sizes": list,           # Size of each revision
    "objects_per_revision": list,     # Object counts per revision
    "content_changes": dict,          # Content change details
    "annotation_count": int,          # Number of annotations
    "form_field_count": int,          # Number of form fields
    "change_types": list,             # List of change type descriptions
    "severity": str,                   # "none"|"minor"|"moderate"|"significant"|"major"
}
```

---

## Logging

Control log verbosity via CLI flags or environment variable:

```bash
# CLI flags
pdf-forensics analyze document.pdf -v      # INFO
pdf-forensics analyze document.pdf -vv     # DEBUG

# Environment variable
export PDF_FORENSICS_LOG_LEVEL=DEBUG
pdf-forensics analyze document.pdf
```

Programmatic control:

```python
from pdf_forensics.logging_config import configure_logging, get_logger

# Set verbosity: 0=WARNING (default), 1=INFO, 2=DEBUG
configure_logging(verbosity=2)

# Get a module-level logger
logger = get_logger(__name__)
logger.info("Analysis started")
```

---

## Architecture

```
pdf_forensics/
  __init__.py          # Public API re-exports
  __main__.py          # python -m pdf_forensics entry point
  cli.py               # Argparse CLI (analyze/verify/compare)
  constants.py         # 44 centralized thresholds and scoring values
  detection.py         # Tampering, security, incremental update detection
  scoring.py           # Integrity, modification, similarity scoring
  reporting.py         # Markdown/JSON report generation
  signature.py         # Digital signature validation (pyHanko)
  pdf_document.py      # PDFDocument context manager (multi-library)
  limits.py            # File size and format validation
  logging_config.py    # Centralized logger setup
  types.py             # TypedDict result type definitions

pdf_source_identifier.py  # Standalone script (backward compat)
verify_signature.py        # Standalone script (backward compat)
compare_pdfs.py            # Standalone script (backward compat)
```

### Analysis Pipeline

```
PDF file
  |
  v
validate_pdf_file() ---------> File size, format, symlink checks
  |
  v
extract_source_fingerprint()
  |
  +-- _detect_incremental_updates()   (detection.py)
  +-- _detect_tampering_indicators()  (detection.py)
  +-- _detect_security_indicators()   (detection.py)
  +-- entropy analysis               (pdf_source_identifier.py)
  |
  v
_calculate_integrity_score()  (scoring.py)
  |
  v
generate_source_report()      (reporting.py)
```

---

## Development

### Running Tests

```bash
# Full test suite
pytest tests/ -q

# With coverage
pytest tests/ --cov=pdf_forensics --cov-report=term-missing

# Specific test file
pytest tests/test_error_paths.py -v
```

### Project Structure

| Directory | Contents |
|-----------|----------|
| `pdf_forensics/` | Core library package |
| `tests/` | Test suite (173 tests, 83% coverage) |
| `tests/fixtures/` | Test PDF files (diverse creators, security threats, tampering) |

### Code Quality Standards

- All scoring thresholds are centralized in `constants.py` (no magic numbers)
- Detection functions return TypedDict instances for type safety
- Resource handles (fitz, pikepdf) use context managers to prevent leaks
- File validation rejects symlinks and non-PDF files
- All PDF object scanning respects configurable limits to prevent resource exhaustion