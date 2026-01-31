"""
Pytest configuration and fixtures for PDF forensics tests

Test fixtures are stored in tests/fixtures/ directory.
These are pre-created PDF files designed for specific test scenarios.
"""

import pytest
import tempfile
import shutil
from pathlib import Path


# Path to fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir():
    """Return the path to the fixtures directory"""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def temp_dir():
    """Create a temporary directory for test output files"""
    temp_path = Path(tempfile.mkdtemp(prefix="pdf_forensics_test_"))
    yield temp_path
    # Cleanup after all tests
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def simple_pdf(fixtures_dir):
    """
    Simple single-page PDF for basic testing.
    - Has complete metadata (creator, producer, title, author)
    - Single page with text
    - No incremental updates
    """
    pdf_path = fixtures_dir / "simple_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def modified_pdf(fixtures_dir):
    """
    PDF with incremental updates (modifications).
    - Original content: Invoice with $100 amount
    - Modified: Added text showing $1000 (simulating tampering)
    - Has 1 incremental update
    """
    pdf_path = fixtures_dir / "modified_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def multi_revision_pdf(fixtures_dir):
    """
    PDF with multiple incremental updates.
    - Original: Contract document
    - 3 incremental updates (revisions)
    - Good for testing revision detection and content change tracking
    """
    pdf_path = fixtures_dir / "multi_revision_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def multipage_pdf(fixtures_dir):
    """
    Multi-page PDF for testing page analysis.
    - 3 pages
    - No incremental updates
    """
    pdf_path = fixtures_dir / "multipage_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def pdf_with_image(fixtures_dir):
    """
    PDF with embedded image.
    - Contains a PNG image
    - Good for testing embedded content analysis
    """
    pdf_path = fixtures_dir / "with_image_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def empty_metadata_pdf(fixtures_dir):
    """
    PDF with empty/missing metadata.
    - No creator, producer, title, author set
    - Good for testing handling of missing metadata
    """
    pdf_path = fixtures_dir / "empty_metadata_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


# Security Threats (4 fixtures)

@pytest.fixture
def javascript_pdf(fixtures_dir):
    """
    PDF with embedded JavaScript (security threat).
    - Contains OpenAction with JavaScript
    - Security risk indicator
    """
    pdf_path = fixtures_dir / "javascript_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def launch_action_pdf(fixtures_dir):
    """
    PDF with launch action (security threat).
    - Contains launch action that could execute external programs
    - Security risk indicator
    """
    pdf_path = fixtures_dir / "launch_action_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def embedded_file_pdf(fixtures_dir):
    """
    PDF with embedded file (security threat).
    - Contains embedded file attachment
    - Potential malware vector
    """
    pdf_path = fixtures_dir / "embedded_file_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def uri_action_pdf(fixtures_dir):
    """
    PDF with URI action (security threat).
    - Contains URI action linking to external resources
    - Could indicate suspicious URLs or tracking
    """
    pdf_path = fixtures_dir / "uri_action_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


# Hidden Content (1 fixture)

@pytest.fixture
def hidden_annotations_pdf(fixtures_dir):
    """
    PDF with hidden annotations.
    - Contains annotations with hidden/invisible visibility
    - Tests detection of hidden content in document
    """
    pdf_path = fixtures_dir / "hidden_annotations_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


# Diverse Creators (6 fixtures)

@pytest.fixture
def adobe_creator_pdf(fixtures_dir):
    """
    PDF created by Adobe tool.
    - Creator: Adobe
    - Tests source identification for Adobe products
    """
    pdf_path = fixtures_dir / "creator_01_adobe_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def chrome_creator_pdf(fixtures_dir):
    """
    PDF created by Chrome (print-to-PDF).
    - Creator: Chrome/Chromium
    - Tests source identification for Chrome products
    """
    pdf_path = fixtures_dir / "creator_02_chrome_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def msword_creator_pdf(fixtures_dir):
    """
    PDF created by Microsoft Word.
    - Creator: Microsoft Word
    - Tests source identification for MS Office products
    """
    pdf_path = fixtures_dir / "creator_03_msword_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def itext_creator_pdf(fixtures_dir):
    """
    PDF created by iText library.
    - Creator: iText
    - Tests source identification for iText products
    """
    pdf_path = fixtures_dir / "creator_04_itext_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def pdfsharp_creator_pdf(fixtures_dir):
    """
    PDF created by PDFSharp library.
    - Creator: PDFSharp
    - Tests source identification for PDFSharp products
    """
    pdf_path = fixtures_dir / "creator_05_pdfsharp_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def libreoffice_creator_pdf(fixtures_dir):
    """
    PDF created by LibreOffice.
    - Creator: LibreOffice
    - Tests source identification for LibreOffice products
    """
    pdf_path = fixtures_dir / "creator_06_libreoffice_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


# Tampering (2 fixtures)

@pytest.fixture
def orphan_objects_pdf(fixtures_dir):
    """
    PDF with orphan objects (unreferenced content).
    - Contains orphan objects not referenced in page tree
    - Indicates deleted or hidden content
    """
    pdf_path = fixtures_dir / "orphan_objects_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


@pytest.fixture
def shadow_attack_pdf(fixtures_dir):
    """
    PDF with shadow attack risk (multiple content streams).
    - Contains multiple content streams per page
    - Could overlay hidden content or create visual inconsistencies
    """
    pdf_path = fixtures_dir / "shadow_attack_test.pdf"
    if not pdf_path.exists():
        pytest.skip(f"Fixture not found: {pdf_path}")
    return pdf_path


# Note: The following fixtures for real data files have been removed.
# Tests that require real data should be skipped if data/ directory is not available.
# Use the fixtures above for all unit tests.
