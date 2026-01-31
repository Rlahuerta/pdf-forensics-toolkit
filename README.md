# PDF Forensics Toolkit

[![Verify Modifications](https://github.com/Rlahuerta/pdf-forensics-toolkit/actions/workflows/verify-modifications.yml/badge.svg)](https://github.com/Rlahuerta/pdf-forensics-toolkit/actions/workflows/verify-modifications.yml)
[![OS - Ubuntu](https://img.shields.io/badge/OS-Ubuntu-orange?logo=ubuntu)](https://ubuntu.com/)
[![Python - 3.11](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform - Linux](https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux)](https://www.linux.org/)

A comprehensive forensic toolkit for analyzing PDF documents to detect tampering, identify document origins, and assess authenticity. Designed for legal professionals, fraud investigators, and compliance teams.

## Purpose

This toolkit helps answer critical questions about PDF documents:

- **Is this document authentic?** - Detect signs of tampering or manipulation
- **Where did this document come from?** - Identify the software system that created it
- **Was this document modified?** - Detect changes made after initial creation
- **Can I trust this document?** - Get an integrity score with actionable recommendations

## Quick Start

### 1. Setup Environment

```bash
# Create environment from YAML (first time)
conda env create -f environment.yml -p ./pdf_forensics_env

# Activate environment
conda activate ./pdf_forensics_env
```

### 2. Analyze Documents

```bash
# Analyze all PDFs in a directory
python pdf_source_identifier.py data/

# Analyze a single file
python pdf_source_identifier.py document.pdf

# Specify output file
python pdf_source_identifier.py data/ my_report.md
```

### 3. Review the Report

Open `source_analysis_report.md` to see:
- Executive summary with flagged documents
- Integrity and tampering scores for each document
- Detailed forensic analysis with recommendations

## Understanding the Report

The generated report is designed to be understood by legal professionals, not just technical experts.

### Key Metrics

| Metric | What It Measures |
|--------|------------------|
| **Integrity Score** (0-100) | Overall trustworthiness based on document structure |
| **Tampering Risk** (0-100) | Likelihood the document was modified after creation |
| **Pipeline Fingerprint** | Unique identifier linking documents to their creation system |

### Integrity Score Guide

| Score | Status | Meaning |
|:-----:|:------:|---------|
| 🟢 90-100 | Excellent | No signs of manipulation |
| 🟡 70-89 | Good | Minor anomalies detected |
| 🟠 50-69 | Questionable | Multiple warning signs |
| 🔴 0-49 | Unreliable | Strong evidence of tampering |

### Tampering Risk Guide

| Score | Risk Level | Action Required |
|:-----:|:----------:|-----------------|
| 0 | ✅ None | Document appears original |
| 1-20 | 🔍 Low | Minor artifacts (often normal) |
| 21-40 | ⚠️ Medium | Verify with document source |
| 41-60 | 🔴 High | Request original document |
| 61-100 | ⛔ Critical | Do not rely on this document |

## What It Detects

### Content Change Detection

When a PDF has been modified through incremental updates, the tool can **recover and compare previous versions** to show exactly what text was added or removed:

- **➕ Text Added** - New text that appeared in a later revision
- **➖ Text Removed** - Text that existed in an earlier revision but was deleted

This is like having a "track changes" view of the document's history. If someone altered an invoice amount or contract term, the original value may still be recoverable.

### Tampering Indicators

| Indicator | Description | Why It Matters |
|-----------|-------------|----------------|
| **Orphan Objects** | Unreferenced data fragments | May contain deleted content |
| **Hidden Layers** | Invisible content in document | Could show different info when printed |
| **Incremental Updates** | Multiple save operations | Each save may represent changes |
| **Document ID Mismatch** | Internal IDs don't match | File was modified after creation |
| **Metadata Inconsistencies** | Conflicting creation info | Dates/authorship may be falsified |
| **Shadow Attack Risk** | Multiple content streams | Could overlay hidden content |

### Security Threats

| Threat | Description |
|--------|-------------|
| **JavaScript** | Embedded code (high risk) |
| **Launch Actions** | Can execute external programs |
| **Embedded Files** | May contain malware |
| **Suspicious URLs** | Links to external resources |

### Source Identification

| Feature | Description |
|---------|-------------|
| **Generation Pipeline** | Software chain that created the PDF |
| **Pipeline Fingerprint** | Unique hash identifying the creation system |
| **Same Source Detection** | Groups documents from the same origin |

## Available Tools

### 1. PDF Source Identifier (Main Tool)

Comprehensive forensic analysis with tampering detection.

```bash
python pdf_source_identifier.py <pdf_or_directory> [output.md]
```

**Output includes:**
- Integrity and tampering scores
- Orphan object detection
- Hidden content detection
- Metadata consistency checks
- Page-level content hashes
- Recommendations for flagged documents

### 2. Signature Verification

Check for digital signatures and extract certificate details.

```bash
python verify_signature.py <pdf_file> [output.md]
```

**Output includes:**
- Digital signature presence and validity
- Certificate information
- Document fingerprints (MD5, SHA1, SHA256)
- Creation system analysis

### 3. PDF Comparison

Compare two PDFs to detect differences.

```bash
python compare_pdfs.py <pdf1> <pdf2> [output.md]
```

## Example Output

```
Analyzing 5 PDF files...

  📄 Invoice_2026.pdf
     → Source: PDFsharp (.NET) (c5f3cc2ad0deb2e1)
  📄 Contract.pdf
     → Source: Adobe Experience Manager Forms (835c6b2eea11967d)
  📄 Receipt.pdf
     → Source: PDFsharp (.NET) (c5f3cc2ad0deb2e1)  ← Same source as Invoice

📊 Found 2 unique source system(s)

✅ Report saved to: source_analysis_report.md
```

### Sample Report Section

```markdown
## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Documents Analyzed | 5 |
| Potentially Compromised | 1 |
| Original/Clean Documents | 4 |

### ⛔ SECURITY ALERT

**1 document(s) show signs of tampering or compromise.**

### Quick Reference

| Document | Integrity | Tampering Risk |
|----------|:---------:|:--------------:|
| Invoice_2026.pdf | 🟢 100 | ✅ None |
| Contract.pdf | 🟡 75 | ⚠️ MEDIUM (40) |
| Receipt.pdf | 🟢 100 | ✅ None |
```

## Technical Details

### Installed Packages

| Package | Purpose |
|---------|---------|
| `PyMuPDF` | Fast PDF parsing and metadata extraction |
| `pikepdf` | Low-level PDF structure analysis |
| `pypdf` | PDF metadata reading |
| `pdfplumber` | Text and table extraction |
| `pyHanko` | Digital signature verification |
| `cryptography` | Certificate parsing |
| `python-magic` | File type detection |

### Command Line Tools

```bash
# Check for malicious elements
pdfid suspicious.pdf

# Interactive PDF analysis
peepdf -i suspicious.pdf
```

## Important Limitations

- This tool analyzes **digital structure**, not content truthfulness
- A clean report doesn't guarantee the document is genuine
- Some legitimate documents may show warnings due to normal processing
- Use this as **one part** of a broader authenticity investigation

## Environment Management

```bash
# Activate
conda activate ./pdf_forensics_env

# Deactivate when done
conda deactivate

# Recreate environment
conda env create -f environment.yml -p ./pdf_forensics_env --force
```

## Running Tests

The toolkit includes a comprehensive test suite to verify all forensic functions work correctly.

```bash
# Activate environment first
conda activate ./pdf_forensics_env

# Run all tests
python -m pytest tests/ -v

# Run tests with coverage report
python -m pytest tests/ --cov=. --cov-report=term-missing

# Run specific test file
python -m pytest tests/test_pdf_source_identifier.py -v

# Run specific test class
python -m pytest tests/test_pdf_source_identifier.py::TestDetectTamperingIndicators -v
```

### Test Coverage

| Test File | Tests | Coverage |
|-----------|:-----:|----------|
| `test_pdf_source_identifier.py` | 53 | Main forensic analysis functions |
| `test_verify_signature.py` | 5 | Digital signature verification |
| `test_compare_pdfs.py` | 5 | PDF comparison functions |

**Total: 63 tests**

### Test Fixtures

Test PDFs are located in `tests/fixtures/` directory:

| Fixture | Description |
|---------|-------------|
| `simple_test.pdf` | Fresh single-page PDF with complete metadata |
| `modified_test.pdf` | PDF with 1 incremental update (simulates tampering) |
| `multi_revision_test.pdf` | PDF with 3 incremental updates |
| `multipage_test.pdf` | 3-page PDF document |
| `with_image_test.pdf` | PDF with embedded PNG image |
| `empty_metadata_test.pdf` | PDF with no metadata |

## Continuous Integration

This project includes an automated verification pipeline that ensures all code modifications are correct before merging.

### Verification Pipeline

The GitHub Actions workflow (`.github/workflows/verify-modifications.yml`) automatically runs on:
- Push to `main`, `develop`, or any `copilot/**` branch
- Pull requests targeting `main` or `develop`
- Manual workflow dispatch

### What Gets Verified

| Check | Description |
|-------|-------------|
| **Python Syntax** | Validates all `.py` files compile without syntax errors |
| **Test Suite** | Runs complete pytest test suite (63+ tests) |
| **Code Coverage** | Generates coverage reports to track test effectiveness |
| **Critical Files** | Ensures all required files and directories are present |

### Pipeline Status

Check the badges at the top of this README to see the current status:

| Badge | Meaning |
|-------|---------|
| ![Verify Modifications](https://img.shields.io/badge/build-passing-brightgreen) | ✅ All tests passing / ❌ Tests failing / 🟡 Running |
| ![OS - Ubuntu](https://img.shields.io/badge/OS-Ubuntu-orange) | Tests run on Ubuntu Linux (latest stable) |
| ![Python - 3.11](https://img.shields.io/badge/Python-3.11-blue) | Tested with Python 3.11 |
| ![Platform - Linux](https://img.shields.io/badge/Platform-Linux-lightgrey) | Linux platform compatibility verified |

**Status Indicators:**
- ✅ Green "passing": All checks passed
- ❌ Red "failing": One or more checks failed
- 🟡 Yellow "running": Pipeline is currently running

### Running Locally

To verify your changes before pushing:

```bash
# 1. Validate Python syntax
python -m py_compile pdf_source_identifier.py verify_signature.py compare_pdfs.py
python -m py_compile pdf_forensics/*.py

# 2. Run tests
python -m pytest tests/ -v

# 3. Check coverage
python -m pytest tests/ --cov=. --cov-report=term-missing
```

## License

MIT
