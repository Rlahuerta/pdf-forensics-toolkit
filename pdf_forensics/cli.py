"""
CLI entry points for PDF Forensics Toolkit.

This module provides argparse-based CLI with subcommands:
- analyze: Identify PDF source and assess integrity
- verify:  Verify digital signatures
- compare: Compare two PDF files
"""

import sys
import json
import os
import argparse
from pathlib import Path

from pdf_forensics.limits import validate_pdf_file
from pdf_forensics.logging_config import configure_logging, get_logger

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf-forensics",
        description="Forensic toolkit for analyzing PDF documents to detect tampering, identify origins, and assess authenticity.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- analyze ---
    analyze_parser = subparsers.add_parser(
        "analyze", help="Identify PDF source and assess integrity",
    )
    analyze_parser.add_argument(
        "files", nargs="+", metavar="file_or_dir",
        help="PDF files or directories to analyze",
    )
    analyze_parser.add_argument(
        "--output", "-o", default="source_analysis_report.md",
        help="Output report path (default: source_analysis_report.md)",
    )
    analyze_parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)",
    )

    # --- verify ---
    verify_parser = subparsers.add_parser(
        "verify", help="Verify digital signatures in a PDF",
    )
    verify_parser.add_argument(
        "file", metavar="pdf_file", help="PDF file to verify",
    )
    verify_parser.add_argument(
        "--output", "-o", default=None,
        help="Output report path (default: <filename>_signature_report.md)",
    )
    verify_parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)",
    )

    # --- compare ---
    compare_parser = subparsers.add_parser(
        "compare", help="Compare two PDF files",
    )
    compare_parser.add_argument(
        "file1", metavar="pdf1", help="First PDF file",
    )
    compare_parser.add_argument(
        "file2", metavar="pdf2", help="Second PDF file",
    )
    compare_parser.add_argument(
        "--output", "-o", default="comparison_report.md",
        help="Output report path (default: comparison_report.md)",
    )
    compare_parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)",
    )

    return parser


def main_source_identifier(args=None):
    """Main CLI entry point for PDF source identification and forensic analysis."""
    from pdf_source_identifier import (
        extract_source_fingerprint,
        analyze_source_similarity,
        generate_source_report,
    )

    parser = _build_parser()
    parsed = parser.parse_args(args)

    # Default to 'analyze' for backward compatibility
    if parsed.command is None:
        parsed.command = "analyze"
        # Treat positional args as files
        remaining = [a for a in (sys.argv[1:] if args is None else args) if not a.startswith("--")]
        if remaining:
            parsed.files = remaining
        else:
            parser.print_help()
            sys.exit(1)

    configure_logging(parsed.verbose)

    if parsed.command == "analyze":
        _run_analyze(parsed, extract_source_fingerprint, analyze_source_similarity, generate_source_report)
    elif parsed.command == "verify":
        _run_verify(parsed)
    elif parsed.command == "compare":
        _run_compare(parsed)
    else:
        parser.print_help()
        sys.exit(1)


def _run_analyze(parsed, extract_source_fingerprint, analyze_source_similarity, generate_source_report):
    """Execute the analyze subcommand."""
    pdf_files = _collect_pdf_files(parsed.files)

    if not pdf_files:
        print("No PDF files found")
        sys.exit(1)

    _validate_files(pdf_files)

    print(f"Analyzing {len(pdf_files)} PDF files...")
    print()

    fingerprints = []
    for pdf_file in pdf_files:
        print(f"  {pdf_file.name}")
        fp = extract_source_fingerprint(str(pdf_file))
        fingerprints.append(fp)
        print(f"     Source: {fp['source_id'].get('system', 'Unknown')} ({fp['source_hash']})")

    print()

    similarity = analyze_source_similarity(fingerprints)

    if "error" not in similarity:
        print(f"Found {similarity['group_count']} unique source system(s)")
        print()
        for source_hash, files in similarity["source_groups"].items():
            fp = next(f for f in fingerprints if f["source_hash"] == source_hash)
            print(f"   {fp['source_id'].get('system', 'Unknown')}: {len(files)} document(s)")
        print()
    else:
        similarity = {
            "source_groups": {fingerprints[0]["source_hash"]: [fingerprints[0]["file"]]},
            "group_count": 1,
            "similarities": [],
        }
        print("Analyzing 1 document (need 2+ for similarity comparison)")
        print()

    if parsed.format == "json":
        output = {"fingerprints": fingerprints, "similarity": similarity}
        print(json.dumps(output, indent=2, default=str))
    else:
        report_path = generate_source_report(fingerprints, similarity, parsed.output)
        print(f"Report saved to: {report_path}")


def _run_verify(parsed):
    """Execute the verify subcommand."""
    from verify_signature import extract_signatures
    from pdf_forensics.reporting import generate_signature_report
    from pdf_forensics.signature import validate_signature as validate_signature_pyhanko

    pdf_path = parsed.file
    is_ok, error_msg = validate_pdf_file(pdf_path)
    if not is_ok:
        print(f"Error: {error_msg}")
        sys.exit(1)

    output_path = parsed.output or (Path(pdf_path).stem + "_signature_report.md")

    print(f"Analyzing: {pdf_path}")

    results = extract_signatures(pdf_path)

    validation_results = validate_signature_pyhanko(pdf_path)
    if validation_results.get("has_signatures"):
        results["pyhanko_validation"] = {
            "signature_valid": validation_results.get("signature_valid", False),
            "intact": validation_results.get("intact", False),
            "validation_errors": validation_results.get("validation_errors", []),
            "signatures": validation_results.get("signatures", []),
        }

    if parsed.format == "json":
        print(json.dumps(results, indent=2, default=str))
    else:
        if results["has_signatures"]:
            print(f"\nFound {results['signature_count']} digital signature(s)")
            if validation_results.get("has_signatures"):
                if validation_results["signature_valid"] and validation_results["intact"]:
                    print("Signatures are cryptographically valid and document is intact")
                elif validation_results["signature_valid"]:
                    print("Signatures are valid but document may have been modified")
                else:
                    print("Signature validation failed")
        else:
            print("\nNo digital signatures found")

        report_path = generate_signature_report(results, output_path)
        print(f"Report saved to: {report_path}")


def _run_compare(parsed):
    """Execute the compare subcommand."""
    from compare_pdfs import compare_pdfs
    from pdf_forensics.reporting import generate_markdown_report

    for pdf_path in [parsed.file1, parsed.file2]:
        is_ok, error_msg = validate_pdf_file(pdf_path)
        if not is_ok:
            print(f"Error: {error_msg}")
            sys.exit(1)

    print(f"Analyzing: {parsed.file1}")
    print(f"Analyzing: {parsed.file2}")

    comparison = compare_pdfs(parsed.file1, parsed.file2)

    if parsed.format == "json":
        print(json.dumps(comparison, indent=2, default=str))
    else:
        report = generate_markdown_report(comparison)
        with open(parsed.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\nReport generated: {parsed.output}")
        print(f"\n{comparison['verdict']}")
        if comparison["differences"]:
            print(f"\nFound {len(comparison['differences'])} differences")


def _collect_pdf_files(paths):
    """Gather PDF files from a mix of file paths and directories."""
    pdf_files = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            pdf_files.extend(sorted(path.glob("*.pdf")))
        elif path.suffix.lower() == ".pdf" and path.exists():
            pdf_files.append(path)
    return pdf_files


def _validate_files(pdf_files):
    """Validate all PDF files before processing."""
    for pdf_file in pdf_files:
        is_ok, error_msg = validate_pdf_file(str(pdf_file))
        if not is_ok:
            print(f"Error: {error_msg}")
            sys.exit(1)


# Keep backward-compatible entry points
main_verify_signature = lambda args=None: _dispatch("verify", args)
main_compare_pdfs = lambda args=None: _dispatch("compare", args)


def _dispatch(command, args=None):
    """Dispatch to main_source_identifier with a forced subcommand."""
    if args is None:
        args = sys.argv[1:]
    # Prepend the subcommand if not already present
    if not args or args[0] not in ("analyze", "verify", "compare"):
        args = [command] + list(args)
    main_source_identifier(args)