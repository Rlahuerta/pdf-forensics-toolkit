"""File size limit and validation utilities for PDF Forensics Toolkit."""

import os
from pathlib import Path

# 100 MB file size limit in bytes
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024

# PDF magic bytes header
PDF_MAGIC_HEADER = b'%PDF-'


def check_file_size(path: str) -> tuple[bool, str]:
    """
    Check if a file exists and is within the size limit.

    Args:
        path: Path to the file to check

    Returns:
        Tuple of (is_ok, error_message):
        - (True, "") if file exists and size is OK
        - (False, error_message) if file doesn't exist or exceeds limit
    """
    # Check if file exists
    file_path = Path(path)
    if not file_path.exists():
        return (False, f"File not found: {path}")

    # Get file size
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        return (False, f"Cannot read file size: {e}")

    # Check size limit
    if file_size > MAX_FILE_SIZE_BYTES:
        size_mb = file_size / (1024 * 1024)
        limit_mb = MAX_FILE_SIZE_BYTES / (1024 * 1024)
        return (
            False,
            f"File size {size_mb:.2f} MB exceeds limit of {limit_mb:.0f} MB"
        )

    return (True, "")


def validate_pdf_file(path: str) -> tuple[bool, str]:
    """
    Validate that a file exists, is within the size limit, and is a valid PDF.

    Checks file existence, size limit, rejects symlinks, and verifies
    the %PDF- magic bytes header.

    Args:
        path: Path to the file to validate

    Returns:
        Tuple of (is_valid, error_message):
        - (True, "") if file is a valid PDF within size limits
        - (False, error_message) with description of the validation failure
    """
    is_ok, error = check_file_size(path)
    if not is_ok:
        return (is_ok, error)

    file_path = Path(path)

    # Reject symlinks for security (prevent path traversal)
    if file_path.is_symlink():
        return (False, f"Symlinks are not supported for security reasons: {path}")

    # Verify %PDF- magic bytes
    try:
        with open(path, 'rb') as f:
            header = f.read(5)
        if header != PDF_MAGIC_HEADER:
            return (False, f"Not a valid PDF file: missing %PDF- header")
    except OSError as e:
        return (False, f"Cannot read file header: {e}")

    return (True, "")
