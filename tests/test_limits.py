"""
Tests for pdf_forensics.limits module.

Tests the check_file_size() and validate_pdf_file() functions which validate
file sizes against the 100 MB limit and verify PDF file integrity.
"""

from unittest.mock import patch
from pdf_forensics.limits import check_file_size, validate_pdf_file, MAX_FILE_SIZE_BYTES


class TestCheckFileSize:
    """Test check_file_size() function for file validation"""
    
    def test_file_within_limit(self, tmp_path):
        """Test that file within size limit passes validation"""
        # Arrange: Create a 500 KB file (well under 100 MB limit)
        test_file = tmp_path / "small.pdf"
        test_file.write_bytes(b"x" * (500 * 1024))
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is True
        assert message == ""
    
    def test_file_exceeds_limit(self, tmp_path):
        """Test that file exceeding size limit fails validation"""
        # Arrange: Create a file over 100 MB
        test_file = tmp_path / "large.pdf"
        # Create 101 MB file
        size_bytes = (101 * 1024 * 1024)
        test_file.write_bytes(b"x" * size_bytes)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is False
        assert "exceed" in message.lower()
        assert "100" in message  # Should mention the 100 MB limit
    
    def test_nonexistent_file(self):
        """Test that nonexistent file returns error"""
        # Act
        is_valid, message = check_file_size("/nonexistent/path/to/file.pdf")
        
        # Assert
        assert is_valid is False
        assert "not found" in message.lower()
    
    def test_directory_path(self, tmp_path):
        """Test that directory path is treated as zero-size and passes"""
        # Arrange
        test_dir = tmp_path / "subdir"
        test_dir.mkdir()
        
        # Act
        is_valid, message = check_file_size(str(test_dir))
        
        # Assert
        assert is_valid is True
        assert message == ""
    
    def test_empty_file(self, tmp_path):
        """Test that empty file (0 bytes) passes validation"""
        # Arrange: Create an empty file
        test_file = tmp_path / "empty.pdf"
        test_file.write_bytes(b"")
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is True
        assert message == ""
    
    def test_exact_limit_boundary(self, tmp_path):
        """Test file exactly at 100 MB limit boundary"""
        # Arrange: Create file exactly 100 MB
        test_file = tmp_path / "exact_limit.pdf"
        exact_size = MAX_FILE_SIZE_BYTES
        test_file.write_bytes(b"x" * exact_size)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert: File at exact limit should be valid (not > limit)
        assert is_valid is True
        assert message == ""
    
    def test_one_byte_over_limit(self, tmp_path):
        """Test file 1 byte over the 100 MB limit"""
        # Arrange: Create file exactly 1 byte over limit
        test_file = tmp_path / "over_by_one.pdf"
        over_size = MAX_FILE_SIZE_BYTES + 1
        test_file.write_bytes(b"x" * over_size)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is False
        assert "exceed" in message.lower()
    
    def test_half_limit_file(self, tmp_path):
        """Test file at 50 MB (half the limit)"""
        # Arrange: Create 50 MB file
        test_file = tmp_path / "half_limit.pdf"
        half_size = MAX_FILE_SIZE_BYTES // 2
        test_file.write_bytes(b"x" * half_size)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is True
        assert message == ""
    
    def test_just_under_limit(self, tmp_path):
        """Test file just under the 100 MB limit"""
        # Arrange: Create file 1 byte under limit
        test_file = tmp_path / "just_under.pdf"
        under_size = MAX_FILE_SIZE_BYTES - 1
        test_file.write_bytes(b"x" * under_size)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is True
        assert message == ""
    
    def test_error_message_contains_sizes(self, tmp_path):
        """Test that error message contains actual file size and limit"""
        # Arrange: Create 105 MB file
        test_file = tmp_path / "oversized.pdf"
        oversized = 105 * 1024 * 1024
        test_file.write_bytes(b"x" * oversized)
        
        # Act
        is_valid, message = check_file_size(str(test_file))
        
        # Assert
        assert is_valid is False
        assert "105" in message  # File size in message
        assert "100" in message  # Limit in message
        assert "MB" in message   # Units in message
    
    def test_oserror_on_getsize(self, tmp_path):
        """Test that OSError during getsize is handled gracefully"""
        # Arrange: Create a valid test file
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"x" * 1024)

        # Act: Mock os.path.getsize to raise OSError
        with patch('os.path.getsize', side_effect=OSError("Permission denied")):
            is_valid, message = check_file_size(str(test_file))

        # Assert
        assert is_valid is False
        assert "Cannot read file size" in message
        assert "Permission denied" in message


class TestValidatePdfFile:
    """Test validate_pdf_file() function for PDF content validation"""

    def test_valid_pdf_file(self, tmp_path):
        """Test that a valid PDF with %PDF- header passes validation"""
        test_file = tmp_path / "valid.pdf"
        test_file.write_bytes(b"%PDF-1.7\nrest of content")

        is_valid, message = validate_pdf_file(str(test_file))

        assert is_valid is True
        assert message == ""

    def test_non_pdf_file(self, tmp_path):
        """Test that a file without %PDF- header fails validation"""
        test_file = tmp_path / "fake.pdf"
        test_file.write_bytes(b"This is not a PDF file at all")

        is_valid, message = validate_pdf_file(str(test_file))

        assert is_valid is False
        assert "%PDF-" in message

    def test_empty_file_fails(self, tmp_path):
        """Test that an empty file fails validation (no header)"""
        test_file = tmp_path / "empty.pdf"
        test_file.write_bytes(b"")

        is_valid, message = validate_pdf_file(str(test_file))

        assert is_valid is False
        assert "%PDF-" in message

    def test_symlink_rejected(self, tmp_path):
        """Test that a symlink is rejected for security"""
        target = tmp_path / "real.pdf"
        target.write_bytes(b"%PDF-1.7\ncontent")
        link = tmp_path / "link.pdf"
        link.symlink_to(target)

        is_valid, message = validate_pdf_file(str(link))

        assert is_valid is False
        assert "Symlink" in message

    def test_oversized_file_fails(self, tmp_path):
        """Test that oversized file fails at size check before header check"""
        test_file = tmp_path / "large.pdf"
        test_file.write_bytes(b"%PDF-1.7\n" + b"x" * (101 * 1024 * 1024))

        is_valid, message = validate_pdf_file(str(test_file))

        assert is_valid is False
        assert "exceed" in message.lower()

    def test_nonexistent_file_fails(self):
        """Test that nonexistent file fails validation"""
        is_valid, message = validate_pdf_file("/nonexistent/file.pdf")

        assert is_valid is False
        assert "not found" in message.lower()
