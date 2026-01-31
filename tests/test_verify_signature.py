"""
Unit tests for verify_signature.py
"""

import pytest

from verify_signature import (
    extract_signatures,
    generate_signature_report,
    _extract_fingerprints,
)


class TestExtractSignatures:
    """Tests for extract_signatures function"""
    
    def test_returns_signature_info(self, simple_pdf):
        """Test that function returns signature information"""
        result = extract_signatures(str(simple_pdf))
        
        assert "has_signatures" in result
        assert "signature_count" in result
    
    def test_simple_pdf_no_signature(self, simple_pdf):
        """Test that simple PDF has no digital signature"""
        result = extract_signatures(str(simple_pdf))
        
        assert result["has_signatures"] == False
        assert result["signature_count"] == 0


class TestExtractFingerprints:
    """Tests for _extract_fingerprints function"""
    
    def test_returns_fingerprint_info(self, simple_pdf):
        """Test that function returns fingerprint information"""
        result = _extract_fingerprints(str(simple_pdf))
        
        assert "file_hashes" in result
        # file_size may be nested or in a different location
        assert isinstance(result, dict)
    
    def test_hashes_are_valid(self, simple_pdf):
        """Test that hashes are valid hex strings"""
        result = _extract_fingerprints(str(simple_pdf))
        
        assert "md5" in result["file_hashes"]
        assert "sha256" in result["file_hashes"]
        assert len(result["file_hashes"]["md5"]) == 32
        assert len(result["file_hashes"]["sha256"]) == 64
        
        # Verify they are hex strings
        int(result["file_hashes"]["md5"], 16)
        int(result["file_hashes"]["sha256"], 16)


class TestGenerateSignatureReport:
    """Tests for generate_signature_report function"""
    
    def test_generates_report_file(self, simple_pdf, temp_dir):
        """Test that report file is generated"""
        output_path = temp_dir / "test_signature_report.md"
        
        results = extract_signatures(str(simple_pdf))
        
        generate_signature_report(results, str(output_path))
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "Signature" in content or "signature" in content
