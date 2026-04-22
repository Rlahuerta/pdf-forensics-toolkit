"""
Tests for error-path handling in PDF Forensics Toolkit.

Covers: corrupted PDF, empty file, non-PDF file, symlink, oversized file (mocked).
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from pdf_forensics.limits import validate_pdf_file, check_file_size
from pdf_forensics.constants import SIMILARITY_SCORE_GOOD_MIN


class TestValidatePdfFile:
    """Tests for validate_pdf_file() edge cases."""

    def test_valid_pdf_passes(self, simple_pdf):
        """Valid PDF should pass validation."""
        is_ok, error = validate_pdf_file(str(simple_pdf))
        assert is_ok is True
        assert error == ""

    def test_non_pdf_file_fails(self, tmp_path):
        """Non-PDF file should fail validation."""
        text_file = tmp_path / "test.txt"
        text_file.write_text("This is not a PDF")
        is_ok, error = validate_pdf_file(str(text_file))
        assert is_ok is False
        assert "PDF" in error

    def test_empty_file_fails(self, tmp_path):
        """Empty file should fail validation."""
        empty_file = tmp_path / "empty.pdf"
        empty_file.write_bytes(b"")
        is_ok, error = validate_pdf_file(str(empty_file))
        assert is_ok is False

    def test_symlink_fails(self, simple_pdf, tmp_path):
        """Symlink to PDF should be rejected for security."""
        link_path = tmp_path / "link.pdf"
        link_path.symlink_to(simple_pdf)
        is_ok, error = validate_pdf_file(str(link_path))
        assert is_ok is False
        assert "Symlink" in error

    def test_nonexistent_file_fails(self):
        """Nonexistent file should fail validation."""
        is_ok, error = validate_pdf_file("/nonexistent/path/file.pdf")
        assert is_ok is False

    def test_truncated_pdf_fails(self, tmp_path):
        """Truncated PDF header should fail validation."""
        bad_file = tmp_path / "truncated.pdf"
        bad_file.write_bytes(b"%PD")
        is_ok, error = validate_pdf_file(str(bad_file))
        assert is_ok is False
        assert "PDF" in error

    def test_oversized_file_fails(self, tmp_path):
        """File exceeding size limit should fail validation (mocked)."""
        big_file = tmp_path / "big.pdf"
        big_file.write_bytes(b"%PDF-1.4 " + b"x" * 100)

        with patch("pdf_forensics.limits.MAX_FILE_SIZE_BYTES", 10):
            is_ok, error = validate_pdf_file(str(big_file))
            assert is_ok is False
            assert "exceeds" in error.lower() or "size" in error.lower()


class TestCorruptedPdfHandling:
    """Tests for handling corrupted PDF files in analysis functions."""

    def test_corrupted_pdf_incremental_updates(self, tmp_path):
        """_detect_incremental_updates should handle corrupted PDF gracefully."""
        from pdf_forensics.detection import _detect_incremental_updates

        # Create a file with PDF header but corrupted content
        corrupted = tmp_path / "corrupted.pdf"
        corrupted.write_bytes(b"%PDF-1.4\n%%EOF\nGARBAGE_DATA")

        # Should not crash, may return results with error
        result = _detect_incremental_updates(str(corrupted))
        assert isinstance(result, dict)
        assert "has_incremental_updates" in result

    def test_corrupted_pdf_tampering_indicators(self, tmp_path):
        """_detect_tampering_indicators should handle corrupted PDF gracefully."""
        from pdf_forensics.detection import _detect_tampering_indicators

        corrupted = tmp_path / "corrupted.pdf"
        corrupted.write_bytes(b"%PDF-1.4\n%%EOF\nGARBAGE")

        result = _detect_tampering_indicators(str(corrupted))
        assert isinstance(result, dict)
        assert "is_compromised" in result

    def test_corrupted_pdf_security_indicators(self, tmp_path):
        """_detect_security_indicators should handle corrupted PDF gracefully."""
        from pdf_forensics.detection import _detect_security_indicators

        corrupted = tmp_path / "corrupted.pdf"
        corrupted.write_bytes(b"%PDF-1.4\n%%EOF\nGARBAGE")

        result = _detect_security_indicators(str(corrupted))
        assert isinstance(result, dict)
        assert "has_javascript" in result


class TestReturnTypeAnnotations:
    """Structural type checks for function return values."""

    def test_tampering_result_types(self, simple_pdf):
        """_detect_tampering_indicators returns correct types."""
        from pdf_forensics.detection import _detect_tampering_indicators

        result = _detect_tampering_indicators(str(simple_pdf))
        assert isinstance(result["is_compromised"], bool)
        assert isinstance(result["risk_score"], int)
        assert isinstance(result["indicators"], list)
        assert isinstance(result["structural_anomalies"], list)
        assert isinstance(result["hidden_content"], list)
        assert isinstance(result["orphan_objects"], list)
        assert isinstance(result["metadata_inconsistencies"], list)
        assert isinstance(result["shadow_attack_risk"], bool)
        assert isinstance(result["recommendations"], list)

    def test_security_result_types(self, simple_pdf):
        """_detect_security_indicators returns correct types."""
        from pdf_forensics.detection import _detect_security_indicators

        result = _detect_security_indicators(str(simple_pdf))
        assert isinstance(result["has_javascript"], bool)
        assert isinstance(result["has_launch_action"], bool)
        assert isinstance(result["has_embedded_files"], bool)
        assert isinstance(result["has_openaction"], bool)
        assert isinstance(result["has_aa"], bool)
        assert isinstance(result["urls_found"], list)
        assert isinstance(result["suspicious_elements"], list)
        assert isinstance(result["risk_level"], str)

    def test_incremental_update_result_types(self, simple_pdf):
        """_detect_incremental_updates returns correct types."""
        from pdf_forensics.detection import _detect_incremental_updates

        result = _detect_incremental_updates(str(simple_pdf))
        assert isinstance(result["has_incremental_updates"], bool)
        assert isinstance(result["update_count"], int)
        assert isinstance(result["was_modified"], bool)
        assert isinstance(result["original_id_match"], bool)

    def test_integrity_score_is_int(self, simple_pdf):
        """_calculate_integrity_score returns an int in valid range."""
        from pdf_forensics.scoring import _calculate_integrity_score
        from pdf_forensics.constants import MIN_SCORE, MAX_SCORE

        fingerprint = {"software": {}, "structure": {}, "incremental_updates": {},
                       "security_indicators": {}, "entropy": {}, "timeline": {},
                       "tampering": {}}
        score = _calculate_integrity_score(fingerprint)
        assert isinstance(score, int)
        assert MIN_SCORE <= score <= MAX_SCORE

    def test_similarity_score_is_float(self):
        """_calculate_similarity returns a float in valid range."""
        from pdf_forensics.scoring import _calculate_similarity
        from pdf_forensics.constants import MIN_SCORE, MAX_SCORE

        fp1 = {
            "software": {"creator_normalized": "a", "producer_normalized": "b"},
            "structure": {"pdf_version": "1.4"},
            "streams": {"filter_signature": "x"},
            "page_layout": {"size_signature": "y"},
            "fonts": ["Helvetica"],
            "naming_patterns": {"has_xfa": False, "has_acroform": False},
        }
        fp2 = {
            "software": {"creator_normalized": "a", "producer_normalized": "b"},
            "structure": {"pdf_version": "1.4"},
            "streams": {"filter_signature": "x"},
            "page_layout": {"size_signature": "y"},
            "fonts": ["Helvetica"],
            "naming_patterns": {"has_xfa": False, "has_acroform": False},
        }
        score = _calculate_similarity(fp1, fp2)
        assert isinstance(score, (int, float))
        assert MIN_SCORE <= score <= MAX_SCORE

    def test_similarity_different_sources(self):
        """_calculate_similarity returns low score for different sources."""
        from pdf_forensics.scoring import _calculate_similarity
        from pdf_forensics.constants import MIN_SCORE, MAX_SCORE

        # Two completely different fingerprints
        fp1 = {
            "software": {"creator_normalized": "Adobe", "producer_normalized": "Acrobat"},
            "structure": {"pdf_version": "1.4"},
            "streams": {"filter_signature": "flate"},
            "page_layout": {"size_signature": "letter"},
            "fonts": ["Helvetica", "Arial"],
            "naming_patterns": {"has_xfa": False, "has_acroform": True},
        }
        fp2 = {
            "software": {"creator_normalized": "Chrome", "producer_normalized": "Skia"},
            "structure": {"pdf_version": "1.7"},
            "streams": {"filter_signature": "dct"},
            "page_layout": {"size_signature": "a4"},
            "fonts": ["DejaVu"],
            "naming_patterns": {"has_xfa": False, "has_acroform": False},
        }
        score = _calculate_similarity(fp1, fp2)
        assert isinstance(score, (int, float))
        assert MIN_SCORE <= score <= MAX_SCORE
        # Different sources should score low
        assert score < SIMILARITY_SCORE_GOOD_MIN