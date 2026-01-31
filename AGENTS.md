# PDF FORENSICS TOOLKIT - KNOWLEDGE BASE

**Generated:** 2026-01-30
**Commit:** 3acf49c
**Branch:** main

## OVERVIEW

Forensic toolkit for PDF tampering detection, source identification, and integrity scoring. Targets legal/compliance use cases. Python 3.11 + PyMuPDF/pikepdf/pyHanko stack.

## STRUCTURE

```
pdf-forensics-toolkit/
├── pdf_source_identifier.py       # MAIN: CLI entry point, comprehensive forensic analysis
├── verify_signature.py            # Digital signature extraction + certificate parsing
├── compare_pdfs.py                # Two-file comparison with diff report
├── pdf_forensics/                 # Core package (Python 3.11+)
│   ├── __init__.py                # Package initialization
│   ├── types.py                   # TypedDict definitions (6 types)
│   ├── detection.py               # Incremental update detection
│   ├── scoring.py                 # Change quantification and integrity scoring
│   ├── signature.py               # Digital signature verification
│   └── [other modules]            # Additional analysis modules
├── tests/                         # pytest suite (85 tests)
│   ├── conftest.py                # Fixtures: simple/modified/multi-revision PDFs
│   ├── fixtures/                  # Test PDF files
│   └── test_*.py                  # Test classes per module
├── data/                          # .gitignored private PDFs for testing
└── environment.yml                # Conda env definition
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Type definitions | `pdf_forensics/types.py` | 6 TypedDict classes for result types |
| Add tampering check | `pdf_source_identifier.py:735` | `_detect_tampering_indicators()` - extend existing |
| Modify integrity scoring | `pdf_source_identifier.py:1454` | `_calculate_integrity_score()` - weighted scoring |
| Add new PDF library pattern | `pdf_source_identifier.py:27` | `KNOWN_PRODUCERS` dict |
| Signature verification | `verify_signature.py:22` | `extract_signatures()` entry point |
| Certificate parsing | `verify_signature.py:325` | `_extract_certificate_info()` |
| Add comparison metric | `compare_pdfs.py:111` | `compare_pdfs()` main function |
| Add test fixture | `tests/conftest.py` | Follow existing pattern; put PDFs in `tests/fixtures/` |
| Report generation | `pdf_source_identifier.py:1710` | `generate_source_report()` - markdown output |

## CODE MAP

### pdf_forensics/types.py (Type Definitions)

| TypedDict | Purpose | Used By |
|-----------|---------|---------|
| `IncrementalUpdateResult` | Result from `_detect_incremental_updates()` | pdf_source_identifier |
| `TamperingResult` | Result from `_detect_tampering_indicators()` | pdf_source_identifier |
| `SecurityResult` | Result from `_detect_security_indicators()` | pdf_source_identifier |
| `IntegrityScoreResult` | Result from `_calculate_integrity_score()` | pdf_source_identifier |
| `SourceFingerprintResult` | Result from `extract_source_fingerprint()` | pdf_source_identifier |
| `SignatureExtractionResult` | Result from `extract_signatures()` | verify_signature |

### pdf_source_identifier.py (Main Module)

| Function | Line | Purpose |
|----------|------|---------|
| `extract_source_fingerprint` | 61 | **Entry point**: Full forensic analysis of single PDF |
| `_detect_incremental_updates` | 251 | Count %%EOF markers, check ID mismatch |
| `_quantify_changes` | 365 | Score modification severity (0-100) |
| `_extract_revision_content` | 523 | Extract text from each PDF revision |
| `_generate_text_diff` | 651 | Compare revision texts, find additions/deletions |
| `_detect_tampering_indicators` | 735 | **Core**: Orphan objects, hidden layers, metadata inconsistencies |
| `_detect_security_indicators` | 1157 | JavaScript, launch actions, embedded files |
| `_analyze_entropy` | 1226 | Stream entropy analysis (obfuscation detection) |
| `_analyze_embedded_content` | 1299 | Image/embedded file inventory |
| `_calculate_integrity_score` | 1454 | **Scoring**: Combine indicators into 0-100 score |
| `_generate_source_hash` | 1517 | Create pipeline fingerprint hash |
| `_classify_source` | 1543 | Match producer/creator to known systems |
| `analyze_source_similarity` | 1636 | Group documents by pipeline fingerprint |
| `generate_source_report` | 1710 | Output: Markdown forensic report |
| `main` | 2377 | CLI entry: directory/files → report |

### verify_signature.py

| Function | Line | Purpose |
|----------|------|---------|
| `extract_signatures` | 22 | Entry point: signature extraction |
| `_extract_fingerprints` | 144 | MD5/SHA1/SHA256 file hashes |
| `_extract_certificate_info` | 325 | Parse X.509 from PKCS#7 |
| `generate_signature_report` | 374 | Markdown signature report |

### compare_pdfs.py

| Function | Line | Purpose |
|----------|------|---------|
| `extract_metadata` | 19 | Get metadata + suspicious indicators |
| `compare_pdfs` | 111 | Diff two PDFs |
| `generate_markdown_report` | 160 | Comparison report output |

## CONVENTIONS

- **Report output**: All tools write markdown to `*_report.md` (gitignored)
- **Function naming**: Public `extract_*`, `analyze_*`, `compare_*`; Private `_detect_*`, `_extract_*`, `_calculate_*`
- **Error handling**: Return error in dict (e.g., `{"error": str(e)}`) rather than raise
- **Type hints**: All public functions use `typing` module hints
- **PDF libraries**: Use `fitz` (PyMuPDF) for fast parsing, `pikepdf` for structure analysis, `pyHanko` for signatures

## ANTI-PATTERNS

- **DO NOT** add runtime dependencies without updating `environment.yml`
- **DO NOT** import from `data/` - it's gitignored and may not exist
- **DO NOT** use `PyPDF2` for new code - use `pypdf` (no "2")
- **NEVER** catch bare `except:` - always `except Exception` minimum
- **AVOID** modifying PDF files in-place - this is a read-only forensic tool

## UNIQUE PATTERNS

- **Revision extraction**: Creates temp files from %%EOF boundaries to read each revision separately (`_extract_revision_content`)
- **Tampering score**: 0-100 scale where 0=clean, 100=compromised (inverse of integrity)
- **Pipeline fingerprint**: Hash of (producer + filters + fonts + page layout) to group docs from same source
- **Orphan detection**: Objects referenced in xref but not in page tree indicate deleted content
- **Shadow attack check**: Multiple content streams per page can overlay hidden content

## COMMANDS

```bash
# Environment setup
conda env create -f environment.yml -p ./pdf_forensics_env
conda activate ./pdf_forensics_env

# Run main analysis
python pdf_source_identifier.py data/                    # Directory
python pdf_source_identifier.py doc.pdf                  # Single file
python pdf_source_identifier.py *.pdf --output report.md # Custom output

# Signature verification
python verify_signature.py document.pdf

# Compare two PDFs
python compare_pdfs.py old.pdf new.pdf

# Run tests
python -m pytest tests/ -v
python -m pytest tests/ --cov=. --cov-report=term-missing

# Run specific test class
python -m pytest tests/test_pdf_source_identifier.py::TestDetectTamperingIndicators -v
```

## NOTES

- **exiftool dependency**: `pyexiftool` requires `exiftool` CLI installed on system
- **Test fixtures**: Pre-created PDFs in `tests/fixtures/` with specific tampering patterns
- **peepdf**: Uses `peepdf-3` fork (Python 3 compatible)
- **Large file**: `pdf_source_identifier.py` is 2450 lines - consider extraction of report generation if extending
- **No packaging**: Scripts run directly, no setup.py/pyproject.toml - add if distributing
