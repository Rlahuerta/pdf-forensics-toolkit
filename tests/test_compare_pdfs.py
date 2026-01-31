"""
Unit tests for compare_pdfs.py
"""

import pytest

from compare_pdfs import (
    extract_metadata,
    compare_pdfs,
    generate_markdown_report,
)


class TestExtractMetadata:
    """Tests for extract_metadata function"""
    
    def test_extracts_basic_metadata(self, simple_pdf):
        """Test extraction of basic metadata"""
        result = extract_metadata(str(simple_pdf))
        
        # Metadata is nested under 'metadata' key
        assert "metadata" in result
        assert "creator" in result["metadata"]
        assert "producer" in result["metadata"]
    
    def test_extracts_page_info(self, simple_pdf):
        """Test extraction of page information"""
        result = extract_metadata(str(simple_pdf))
        
        # Page count is in file_info
        assert "file_info" in result
        # Look for page info in file_type string
        assert "pages" in result["file_info"].get("file_type", "")


class TestComparePdfs:
    """Tests for compare_pdfs function"""
    
    def test_compares_two_pdfs(self, simple_pdf, modified_pdf):
        """Test comparison of two PDFs"""
        result = compare_pdfs(str(simple_pdf), str(modified_pdf))
        
        # Keys are file1 and file2
        assert "file1" in result
        assert "file2" in result
        assert isinstance(result, dict)
    
    def test_identical_pdfs(self, simple_pdf):
        """Test that identical PDFs are compared correctly"""
        result = compare_pdfs(str(simple_pdf), str(simple_pdf))
        
        assert result is not None


class TestGenerateMarkdownReport:
    """Tests for generate_markdown_report function"""
    
    def test_generates_markdown(self, simple_pdf, modified_pdf):
        """Test markdown report generation"""
        comparison = compare_pdfs(str(simple_pdf), str(modified_pdf))
        
        report = generate_markdown_report(comparison)
        
        assert isinstance(report, str)
        assert len(report) > 0
        assert "#" in report  # Should have markdown headers
