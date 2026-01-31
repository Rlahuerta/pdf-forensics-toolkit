# Changelog

All notable changes to the PDF Forensics Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-31

### Initial Release

This is the first stable release of the PDF Forensics Toolkit - a comprehensive forensic toolkit for analyzing PDF documents to detect tampering, identify document origins, and assess authenticity.

#### Features

##### Core Analysis Tools
- **PDF Source Identifier**: Comprehensive forensic analysis with tampering detection
  - Integrity scoring (0-100 scale) for document trustworthiness assessment
  - Tampering risk detection (0-100 scale) with actionable alerts
  - Incremental update detection and analysis
  - Content change detection with text diff visualization
  - Previous version recovery from incremental updates
  - Orphan object detection (unreferenced data fragments)
  - Hidden layer and content detection
  - Metadata consistency verification
  - Document ID mismatch detection
  - Shadow attack risk assessment
  - Page-level content hashing
  - Security threat detection (JavaScript, launch actions, embedded files)
  - Source identification and pipeline fingerprinting
  - Same-source document grouping
  - Detailed markdown report generation

- **Digital Signature Verification**: Certificate and signature analysis
  - Digital signature presence and validity checking
  - X.509 certificate information extraction
  - Document fingerprint generation (MD5, SHA1, SHA256)
  - Creation system analysis from signatures

- **PDF Comparison**: Side-by-side document comparison
  - Metadata difference detection
  - Content change identification
  - Suspicious indicator comparison
  - Detailed comparison reports

##### Pipeline Fingerprinting
- Unique hash generation based on document creation pipeline
- Identifies documents from the same source system
- Supports detection of common PDF generation tools:
  - Adobe products (Acrobat, InDesign, Photoshop, etc.)
  - Microsoft Office suite
  - Web-to-PDF converters (Chrome, Playwright, wkhtmltopdf)
  - Programming libraries (ReportLab, PDFKit, pdfmake, etc.)
  - Document management systems (Salesforce, Adobe Experience Manager)

##### Command-Line Interface
- Three console commands available after installation:
  - `pdf-forensics`: Main forensic analysis tool
  - `verify-pdf-sig`: Digital signature verification
  - `compare-pdfs`: Document comparison utility
- Support for single file or directory batch processing
- Customizable output file paths
- User-friendly progress indicators

##### Report Generation
- Markdown format for easy reading and sharing
- Executive summary with key findings
- Security alerts for potentially compromised documents
- Quick reference tables with visual indicators
- Detailed forensic analysis per document
- Actionable recommendations based on findings

##### Package Management
- Python 3.11+ support
- Conda environment configuration included
- Pip installation support with optional dev dependencies
- Comprehensive dependency management via pyproject.toml
- Hatchling build backend

##### Testing Infrastructure
- 63 comprehensive test cases
- Test fixtures for various PDF scenarios
- Coverage reporting integration
- pytest-based test suite
- GitHub Actions CI/CD integration

#### Technical Stack

##### Core Dependencies
- PyMuPDF (≥1.26.0): Fast PDF parsing and metadata extraction
- pikepdf (≥10.0.0): Low-level PDF structure analysis
- pypdf (≥6.0.0): PDF metadata reading
- pdfplumber (≥0.11.0): Text and table extraction
- pyHanko (≥0.32.0): Digital signature verification
- cryptography (≥46.0.0): Certificate parsing
- python-magic (≥0.4.27): File type detection
- Pillow (≥12.0.0): Image processing
- pyexiftool (≥0.5.0): Metadata extraction
- pdfid (≥1.1.0): PDF structure analysis
- peepdf-3 (≥5.0.0): Interactive PDF analysis
- endesive (≥2.19.0): PDF signature support
- ReportLab (≥4.0.0): PDF generation

##### Platform Support
- Tested on Ubuntu (via GitHub Actions CI)
- macOS compatible (with Homebrew dependencies)
- Python 3.11 and 3.12 support

#### Documentation
- Comprehensive README with quick start guide
- Detailed user guide for legal professionals
- Technical documentation for developers
- Example outputs and report samples
- Troubleshooting and limitations guide
- Test coverage documentation

#### Known Limitations
- Analyzes digital structure, not content truthfulness
- Some legitimate documents may show warnings due to normal processing
- Should be used as part of broader authenticity investigation

[1.0.0]: https://github.com/Rlahuerta/pdf-forensics-toolkit/releases/tag/v1.0.0
