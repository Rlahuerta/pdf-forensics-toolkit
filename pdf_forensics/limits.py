"""File size limit utilities for PDF Forensics Toolkit."""

import os
from pathlib import Path

# 100 MB file size limit in bytes
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024


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
