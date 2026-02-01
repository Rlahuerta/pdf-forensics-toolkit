"""
Unit tests for pdf_forensics.signature module

Tests signature validation functions with both pyHanko available and unavailable scenarios.
"""

from unittest.mock import patch, MagicMock, mock_open

from pdf_forensics.signature import (
    validate_signature,
    _validate_signature_field,
    is_pyhanko_available,
)


class TestValidateSignature:
    """Test validate_signature() with various scenarios"""
    
    def test_handles_missing_pyhanko(self, simple_pdf, monkeypatch):
        """Test graceful degradation when pyHanko not installed"""
        import pdf_forensics.signature as sig_module
        monkeypatch.setattr(sig_module, 'PYHANKO_AVAILABLE', False)
        
        result = validate_signature(str(simple_pdf))
        
        assert "validation_errors" in result
        assert len(result["validation_errors"]) > 0
        assert result["validation_errors"][0]["error"] == "pyHanko not available"
        assert "pyHanko" in result["validation_errors"][0]["detail"]
        assert result["signature_valid"] is False
        assert result["has_signatures"] is False
    
    def test_handles_nonexistent_file(self):
        """Test handling of nonexistent file"""
        result = validate_signature("nonexistent.pdf")
        
        assert "validation_errors" in result
        assert len(result["validation_errors"]) > 0
        assert result["validation_errors"][0]["error"] == "File not found"
        assert result["signature_valid"] is False
    
    @patch('pdf_forensics.signature.open', new_callable=mock_open, read_data=b'%PDF-1.7')
    @patch('pdf_forensics.signature.PdfFileReader')
    @patch('pdf_forensics.signature.Path')
    def test_handles_pdf_without_signatures(self, mock_path_class, mock_reader_class, mock_file):
        """Test PDF without signature fields"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.name = "test.pdf"
        mock_path_class.return_value = mock_path
        
        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader
        
        mock_reader.root.get.return_value = {}
        
        result = validate_signature("test.pdf")
        
        assert result["has_signatures"] is False
        assert result["signature_count"] == 0
        assert result["signature_valid"] is False
        assert len(result["signatures"]) == 0
    
    @patch('pdf_forensics.signature.open', new_callable=mock_open, read_data=b'%PDF-1.7')
    @patch('pdf_forensics.signature.PdfFileReader')
    @patch('pdf_forensics.signature.Path')
    def test_handles_pdf_with_non_signature_fields(self, mock_path_class, mock_reader_class, mock_file):
        """Test PDF with AcroForm but no signature fields"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.name = "test.pdf"
        mock_path_class.return_value = mock_path
        
        mock_reader = MagicMock()
        mock_reader_class.return_value = mock_reader
        
        mock_text_obj = MagicMock()
        mock_text_obj.get.return_value = '/Tx'
        
        mock_text_field = MagicMock()
        mock_text_field.get_object.return_value = mock_text_obj
        
        mock_acroform = MagicMock()
        mock_acroform.get.return_value = [mock_text_field]
        mock_reader.root.get.side_effect = lambda key, default=None: mock_acroform if key == '/AcroForm' else default
        
        result = validate_signature("test.pdf")
        
        assert result["has_signatures"] is False
        assert result["signature_count"] == 0
    
    @patch('pdf_forensics.signature.Path')
    @patch('pdf_forensics.signature.open', side_effect=IOError("Permission denied"))
    def test_handles_file_read_error(self, mock_file, mock_path_class):
        """Test handling of file read errors"""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.name = "protected.pdf"
        mock_path_class.return_value = mock_path
        
        result = validate_signature("protected.pdf")
        
        assert "validation_errors" in result
        assert len(result["validation_errors"]) > 0
        assert result["validation_errors"][0]["error"] == "Validation failed"
        assert "Permission denied" in result["validation_errors"][0]["detail"]


class TestValidateSignatureField:
    """Test _validate_signature_field() internal logic"""
    
    @patch('pdf_forensics.signature.validate_pdf_signature')
    def test_validates_signature_field_with_pyhanko(self, mock_validate_pdf):
        """Test signature field validation with pyHanko"""
        mock_reader = MagicMock()
        
        mock_sig_field = {
            '/T': 'Signature1',
            '/V': {
                '/Name': 'John Doe',
                '/M': "D:20260201120000+00'00'",
                '/Filter': '/Adobe.PPKLite',
            }
        }
        
        mock_sig_obj = MagicMock()
        mock_reader.embedded_signatures = [mock_sig_obj]
        
        mock_validation_result = MagicMock()
        mock_validation_result.valid = True
        mock_validation_result.intact = True
        mock_validation_result.coverage = "ENTIRE_FILE"
        
        mock_signer = MagicMock()
        mock_signer.subject.rfc4514_string.return_value = "CN=John Doe,O=TestOrg"
        mock_validation_result.signer_info = mock_signer
        
        mock_cert = MagicMock()
        mock_cert.subject.rfc4514_string.return_value = "CN=John Doe"
        mock_cert.issuer.rfc4514_string.return_value = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before_utc.isoformat.return_value = "2025-01-01T00:00:00+00:00"
        mock_cert.not_valid_after_utc.isoformat.return_value = "2027-01-01T00:00:00+00:00"
        mock_validation_result.signer_cert = mock_cert
        mock_validation_result.validation_errors = []
        
        mock_validate_pdf.return_value = mock_validation_result
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["index"] == 0
        assert result["field_name"] == "Signature1"
        assert result["valid"] is True
        assert result["intact"] is True
        assert result["coverage"] == "ENTIRE_FILE"
        assert result["signer"] == "CN=John Doe,O=TestOrg"
        assert len(result["errors"]) == 0
        assert len(result["certificate_chain"]) == 1
    
    def test_handles_missing_signature_value(self):
        """Test handling of signature field without /V entry"""
        mock_reader = MagicMock()
        mock_sig_field = {
            '/T': 'EmptySignature',
        }
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["index"] == 0
        assert result["field_name"] == "EmptySignature"
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert result["errors"][0]["error"] == "No signature value"
    
    def test_handles_missing_embedded_signature(self):
        """Test handling when embedded signature object not found"""
        mock_reader = MagicMock()
        mock_reader.embedded_signatures = []
        
        mock_sig_field = {
            '/T': 'Signature1',
            '/V': {'/Name': 'John Doe'}
        }
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert result["errors"][0]["error"] == "Signature object not found"
    
    @patch('pdf_forensics.signature.validate_pdf_signature')
    def test_extracts_basic_signature_metadata(self, mock_validate_pdf):
        """Test extraction of basic signature metadata"""
        mock_reader = MagicMock()
        
        mock_sig_field = {
            '/T': 'LegalSignature',
            '/V': {
                '/Name': 'Jane Smith',
                '/M': "D:20260115093000-05'00'",
                '/Reason': 'Contract approval',
                '/Location': 'New York, NY',
            }
        }
        
        mock_sig_obj = MagicMock()
        mock_reader.embedded_signatures = [mock_sig_obj]
        
        mock_validation_result = MagicMock()
        mock_validation_result.valid = True
        mock_validation_result.intact = True
        mock_validation_result.coverage = "ENTIRE_FILE"
        mock_validation_result.signer_info = None
        mock_validation_result.signer_cert = None
        mock_validation_result.validation_errors = []
        
        mock_validate_pdf.return_value = mock_validation_result
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["field_name"] == "LegalSignature"
        assert result["signer"] == "Jane Smith"
        assert result["signing_time"] == "D:20260115093000-05'00'"
    
    @patch('pdf_forensics.signature.validate_pdf_signature')
    def test_handles_validation_errors(self, mock_validate_pdf):
        """Test handling of validation errors from pyHanko"""
        mock_reader = MagicMock()
        
        mock_sig_field = {
            '/T': 'InvalidSignature',
            '/V': {'/Name': 'Hacker'}
        }
        
        mock_sig_obj = MagicMock()
        mock_reader.embedded_signatures = [mock_sig_obj]
        
        mock_validation_result = MagicMock()
        mock_validation_result.valid = False
        mock_validation_result.intact = False
        mock_validation_result.coverage = "UNKNOWN"
        mock_validation_result.validation_errors = ["Certificate expired", "Signature modified"]
        mock_validation_result.signer_info = None
        mock_validation_result.signer_cert = None
        
        mock_validate_pdf.return_value = mock_validation_result
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["valid"] is False
        assert result["intact"] is False
        assert len(result["errors"]) == 2
        assert result["errors"][0]["error"] == "Validation error"
    
    @patch('pdf_forensics.signature.validate_pdf_signature')
    def test_handles_certificate_validation_error(self, mock_validate_pdf):
        """Test handling of certificate validation exceptions"""
        mock_reader = MagicMock()
        mock_sig_field = {
            '/T': 'UntrustedSignature',
            '/V': {'/Name': 'Unknown'}
        }
        
        mock_sig_obj = MagicMock()
        mock_reader.embedded_signatures = [mock_sig_obj]
        
        mock_validate_pdf.side_effect = Exception("Certificate validation failed: untrusted chain")
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert result["errors"][0]["error"] == "Signature validation failed"
        assert "Certificate validation failed" in result["errors"][0]["detail"]
    
    def test_handles_field_processing_exception(self):
        """Test handling of general exceptions during field processing"""
        mock_reader = MagicMock()
        mock_sig_field = {
            '/V': {'/Name': 'Test'}
        }
        mock_sig_field['/T'] = MagicMock(side_effect=Exception("PDF parsing error"))
        
        result = _validate_signature_field(mock_reader, mock_sig_field, 0, None)
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0


class TestIsPyhankoAvailable:
    """Test is_pyhanko_available() helper function"""
    
    def test_returns_availability_status(self):
        """Test function returns correct pyHanko availability status"""
        result = is_pyhanko_available()
        assert isinstance(result, bool)
