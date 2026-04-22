"""
CLI entry point for pdf_forensics package.

Allows running the toolkit via: python -m pdf_forensics [command]

Supported commands:
  analyze   - Identify PDF source and assess integrity (default)
  verify    - Verify digital signatures
  compare   - Compare two PDF files
"""

from pdf_forensics.cli import main_source_identifier

if __name__ == "__main__":
    main_source_identifier()