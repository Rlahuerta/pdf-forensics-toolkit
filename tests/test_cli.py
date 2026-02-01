"""
Unit tests for pdf_forensics.cli module
"""

import pytest
import sys
from unittest.mock import patch

from pdf_forensics.cli import (
    main_source_identifier,
    main_verify_signature,
    main_compare_pdfs,
)


class TestMainSourceIdentifier:
    """Tests for main_source_identifier CLI function"""
    
    def test_no_arguments_exits(self):
        """Test that function exits when no arguments provided"""
        with patch.object(sys, 'argv', ['pdf_forensics']):
            with pytest.raises(SystemExit) as exc_info:
                main_source_identifier()
            assert exc_info.value.code == 1
    
    def test_single_file_analysis(self, simple_pdf, tmp_path):
        """Test analyzing single PDF file"""
        output_file = tmp_path / "test_report.md"
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(simple_pdf)]):
            with patch('pdf_source_identifier.generate_source_report') as mock_report:
                mock_report.return_value = str(output_file)
                main_source_identifier()
                
                # Verify report generation was called
                assert mock_report.called
    
    def test_directory_analysis(self, fixtures_dir, tmp_path):
        """Test analyzing directory of PDFs"""
        output_file = tmp_path / "test_report.md"
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(fixtures_dir)]):
            with patch('pdf_source_identifier.generate_source_report') as mock_report:
                mock_report.return_value = str(output_file)
                main_source_identifier()
                
                # Verify report generation was called
                assert mock_report.called
    
    def test_output_file_specified(self, simple_pdf, tmp_path):
        """Test custom output file path"""
        output_file = tmp_path / "custom_report.md"
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(simple_pdf), '--output', str(output_file)]):
            with patch('pdf_source_identifier.generate_source_report') as mock_report:
                mock_report.return_value = str(output_file)
                main_source_identifier()
                
                # Verify report was called with custom output path
                assert mock_report.called
                call_args = mock_report.call_args
                assert call_args[0][2] == str(output_file)
    
    def test_multiple_files_analysis(self, simple_pdf, modified_pdf, tmp_path):
        """Test analyzing multiple PDF files"""
        output_file = tmp_path / "multi_report.md"
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(simple_pdf), str(modified_pdf)]):
            with patch('pdf_source_identifier.generate_source_report') as mock_report:
                mock_report.return_value = str(output_file)
                main_source_identifier()
                
                # Verify report generation was called
                assert mock_report.called
                # Verify multiple files were processed
                fingerprints = mock_report.call_args[0][0]
                assert len(fingerprints) == 2
    
    def test_nonexistent_file_exits(self):
        """Test that nonexistent file causes exit"""
        with patch.object(sys, 'argv', ['pdf_forensics', 'nonexistent.pdf']):
            with pytest.raises(SystemExit) as exc_info:
                main_source_identifier()
            assert exc_info.value.code == 1
    
    def test_file_size_limit_enforcement(self, simple_pdf):
        """Test that file size limit is checked"""
        with patch.object(sys, 'argv', ['pdf_forensics', str(simple_pdf)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                # Simulate file too large
                mock_check.return_value = (False, "File size exceeds limit")
                
                with pytest.raises(SystemExit) as exc_info:
                    main_source_identifier()
                assert exc_info.value.code == 1
    
    def test_no_pdf_files_found_exits(self, tmp_path):
        """Test that empty directory causes exit"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(empty_dir)]):
            with pytest.raises(SystemExit) as exc_info:
                main_source_identifier()
            assert exc_info.value.code == 1


class TestMainVerifySignature:
    """Tests for main_verify_signature CLI function"""
    
    def test_no_arguments_exits(self):
        """Test that function exits when no arguments provided"""
        with patch.object(sys, 'argv', ['verify_signature']):
            with pytest.raises(SystemExit) as exc_info:
                main_verify_signature()
            assert exc_info.value.code == 1
    
    def test_signature_verification_flow(self, simple_pdf, tmp_path):
        """Test signature verification flow"""
        output_file = tmp_path / "sig_report.md"
        
        with patch.object(sys, 'argv', ['verify_signature', str(simple_pdf)]):
            with patch('verify_signature.extract_signatures') as mock_extract:
                with patch('pdf_forensics.signature.validate_signature') as mock_validate:
                    with patch('pdf_forensics.reporting.generate_signature_report') as mock_report:
                        # Mock return values
                        mock_extract.return_value = {
                            "has_signatures": False,
                            "signature_count": 0,
                        }
                        mock_validate.return_value = {"has_signatures": False}
                        mock_report.return_value = str(output_file)
                        
                        main_verify_signature()
                        
                        # Verify all functions were called
                        assert mock_extract.called
                        assert mock_validate.called
                        assert mock_report.called
    
    def test_signature_verification_with_output(self, simple_pdf, tmp_path):
        """Test signature verification with custom output file"""
        output_file = tmp_path / "custom_sig_report.md"
        
        with patch.object(sys, 'argv', ['verify_signature', str(simple_pdf), str(output_file)]):
            with patch('verify_signature.extract_signatures') as mock_extract:
                with patch('pdf_forensics.signature.validate_signature') as mock_validate:
                    with patch('pdf_forensics.reporting.generate_signature_report') as mock_report:
                        # Mock return values
                        mock_extract.return_value = {
                            "has_signatures": False,
                            "signature_count": 0,
                        }
                        mock_validate.return_value = {"has_signatures": False}
                        mock_report.return_value = str(output_file)
                        
                        main_verify_signature()
                        
                        # Verify report was called with custom output path
                        assert mock_report.called
                        call_args = mock_report.call_args
                        assert call_args[0][1] == str(output_file)
    
    def test_signature_found_message(self, simple_pdf, tmp_path, capsys):
        """Test output when signature is found"""
        output_file = tmp_path / "sig_report.md"
        
        with patch.object(sys, 'argv', ['verify_signature', str(simple_pdf)]):
            with patch('verify_signature.extract_signatures') as mock_extract:
                with patch('pdf_forensics.signature.validate_signature') as mock_validate:
                    with patch('pdf_forensics.reporting.generate_signature_report') as mock_report:
                        # Mock signature found
                        mock_extract.return_value = {
                            "has_signatures": True,
                            "signature_count": 1,
                        }
                        mock_validate.return_value = {
                            "has_signatures": True,
                            "signature_valid": True,
                            "intact": True,
                        }
                        mock_report.return_value = str(output_file)
                        
                        main_verify_signature()
                        
                        # Check output
                        captured = capsys.readouterr()
                        assert "Found 1 digital signature(s)" in captured.out
    
    def test_file_size_limit_enforcement(self, simple_pdf):
        """Test that file size limit is checked"""
        with patch.object(sys, 'argv', ['verify_signature', str(simple_pdf)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                # Simulate file too large
                mock_check.return_value = (False, "File size exceeds limit")
                
                with pytest.raises(SystemExit) as exc_info:
                    main_verify_signature()
                assert exc_info.value.code == 1


class TestMainComparePdfs:
    """Tests for main_compare_pdfs CLI function"""
    
    def test_no_arguments_exits(self):
        """Test that function exits when insufficient arguments provided"""
        with patch.object(sys, 'argv', ['compare_pdfs']):
            with pytest.raises(SystemExit) as exc_info:
                main_compare_pdfs()
            assert exc_info.value.code == 1
    
    def test_one_argument_exits(self, simple_pdf):
        """Test that function exits when only one file provided"""
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf)]):
            with pytest.raises(SystemExit) as exc_info:
                main_compare_pdfs()
            assert exc_info.value.code == 1
    
    def test_compare_two_pdfs(self, simple_pdf, modified_pdf, tmp_path):
        """Test comparing two PDF files"""
        output_file = tmp_path / "comparison_report.md"
        
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf), str(modified_pdf)]):
            with patch('compare_pdfs.compare_pdfs') as mock_compare:
                with patch('pdf_forensics.reporting.generate_markdown_report') as mock_report:
                    # Mock return values
                    mock_compare.return_value = {
                        "verdict": "Files are different",
                        "differences": [{"field": "content", "difference": "modified"}],
                    }
                    mock_report.return_value = "# Comparison Report"
                    
                    main_compare_pdfs()
                    
                    # Verify functions were called
                    assert mock_compare.called
                    assert mock_report.called
                    # Verify files were compared
                    call_args = mock_compare.call_args
                    assert call_args[0][0] == str(simple_pdf)
                    assert call_args[0][1] == str(modified_pdf)
    
    def test_compare_with_output_file(self, simple_pdf, modified_pdf, tmp_path):
        """Test comparing with custom output file"""
        output_file = tmp_path / "custom_comparison.md"
        
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf), str(modified_pdf), str(output_file)]):
            with patch('compare_pdfs.compare_pdfs') as mock_compare:
                with patch('pdf_forensics.reporting.generate_markdown_report') as mock_report:
                    # Mock return values
                    mock_compare.return_value = {
                        "verdict": "Files are different",
                        "differences": [],
                    }
                    mock_report.return_value = "# Comparison Report"
                    
                    main_compare_pdfs()
                    
                    # Verify output file was created
                    assert output_file.exists()
    
    def test_file_size_limit_enforcement_first_file(self, simple_pdf, modified_pdf):
        """Test that file size limit is checked for first file"""
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf), str(modified_pdf)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                # Simulate first file too large
                def size_check(path):
                    if path == str(simple_pdf):
                        return (False, "File size exceeds limit")
                    return (True, "")
                
                mock_check.side_effect = size_check
                
                with pytest.raises(SystemExit) as exc_info:
                    main_compare_pdfs()
                assert exc_info.value.code == 1
    
    def test_file_size_limit_enforcement_second_file(self, simple_pdf, modified_pdf):
        """Test that file size limit is checked for second file"""
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf), str(modified_pdf)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                # Simulate second file too large
                def size_check(path):
                    if path == str(modified_pdf):
                        return (False, "File size exceeds limit")
                    return (True, "")
                
                mock_check.side_effect = size_check
                
                with pytest.raises(SystemExit) as exc_info:
                    main_compare_pdfs()
                assert exc_info.value.code == 1
    
    def test_differences_reported(self, simple_pdf, modified_pdf, tmp_path, capsys):
        """Test that differences are reported in output"""
        output_file = tmp_path / "comparison_report.md"
        
        with patch.object(sys, 'argv', ['compare_pdfs', str(simple_pdf), str(modified_pdf)]):
            with patch('compare_pdfs.compare_pdfs') as mock_compare:
                with patch('pdf_forensics.reporting.generate_markdown_report') as mock_report:
                    # Mock return values with differences
                    mock_compare.return_value = {
                        "verdict": "Files are different",
                        "differences": [
                            {"field": "content", "difference": "modified"},
                            {"field": "metadata", "difference": "changed"},
                        ],
                    }
                    mock_report.return_value = "# Comparison Report"
                    
                    main_compare_pdfs()
                    
                    # Check output
                    captured = capsys.readouterr()
                    assert "Found 2 differences" in captured.out


class TestFileSizeLimit:
    """Tests for file size limit enforcement across all CLI functions"""
    
    def test_source_identifier_enforces_limit(self, tmp_path):
        """Test that source identifier enforces file size limit"""
        # Create a mock large file
        large_file = tmp_path / "large.pdf"
        large_file.write_bytes(b"PDF" * 100)  # Small file, but we'll mock size check
        
        with patch.object(sys, 'argv', ['pdf_forensics', str(large_file)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                mock_check.return_value = (False, "File size 150.00 MB exceeds limit of 100 MB")
                
                with pytest.raises(SystemExit) as exc_info:
                    main_source_identifier()
                assert exc_info.value.code == 1
    
    def test_verify_signature_enforces_limit(self, tmp_path):
        """Test that verify signature enforces file size limit"""
        large_file = tmp_path / "large.pdf"
        large_file.write_bytes(b"PDF" * 100)
        
        with patch.object(sys, 'argv', ['verify_signature', str(large_file)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                mock_check.return_value = (False, "File size 150.00 MB exceeds limit of 100 MB")
                
                with pytest.raises(SystemExit) as exc_info:
                    main_verify_signature()
                assert exc_info.value.code == 1
    
    def test_compare_pdfs_enforces_limit(self, tmp_path):
        """Test that compare PDFs enforces file size limit"""
        large_file1 = tmp_path / "large1.pdf"
        large_file2 = tmp_path / "large2.pdf"
        large_file1.write_bytes(b"PDF" * 100)
        large_file2.write_bytes(b"PDF" * 100)
        
        with patch.object(sys, 'argv', ['compare_pdfs', str(large_file1), str(large_file2)]):
            with patch('pdf_forensics.cli.check_file_size') as mock_check:
                mock_check.return_value = (False, "File size 150.00 MB exceeds limit of 100 MB")
                
                with pytest.raises(SystemExit) as exc_info:
                    main_compare_pdfs()
                assert exc_info.value.code == 1
