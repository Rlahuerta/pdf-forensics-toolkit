"""
CLI entry point for pdf_forensics package.

Allows running the toolkit via: python -m pdf_forensics [command]

Supported commands:
  analyze   - Identify PDF source and assess integrity (default)
  verify    - Verify digital signatures
  compare   - Compare two PDF files
"""

import sys

from pdf_forensics.cli import main_source_identifier, main_verify_signature, main_compare_pdfs


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print("Usage: python -m pdf_forensics <command> [args]")
        print()
        print("Commands:")
        print("  analyze   Identify PDF source and assess integrity (default)")
        print("  verify    Verify digital signatures in a PDF")
        print("  compare   Compare two PDF files")
        print()
        print("Run 'python -m pdf_forensics <command>' for command-specific help.")
        sys.exit(0)

    command = sys.argv[1]
    # Remove the subcommand from argv so the CLI functions see their expected args
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    if command == "analyze":
        main_source_identifier()
    elif command == "verify":
        main_verify_signature()
    elif command == "compare":
        main_compare_pdfs()
    else:
        # Default: treat unknown command as analyze (backward compatible)
        sys.argv = [sys.argv[0]] + [command] + sys.argv[1:]
        main_source_identifier()


if __name__ == "__main__":
    main()