"""
CLI entry points for PDF Forensics Toolkit.

This module consolidates the main() functions from the original scripts:
- pdf_source_identifier.py
- verify_signature.py
- compare_pdfs.py

All functions include file size checks for safety.
"""

import sys
import json
from pathlib import Path

from pdf_forensics.limits import check_file_size
from pdf_forensics.logging_config import get_logger

logger = get_logger(__name__)


def main_source_identifier():
    """
    Main CLI entry point for PDF source identification and forensic analysis.
    
    Originally from pdf_source_identifier.py main() function.
    Analyzes PDF documents to detect tampering, identify origins, and assess integrity.
    """
    # Import here to avoid circular dependencies
    from pdf_source_identifier import (
        extract_source_fingerprint,
        analyze_source_similarity,
        generate_source_report,
    )
    
    if len(sys.argv) < 2:
        print("Usage: python -m pdf_forensics <pdf_files_or_directory> [--output report.md]")
        print("\nIdentifies the source system of PDF documents and groups by origin.")
        print("Examples:")
        print("  python -m pdf_forensics data/")
        print("  python -m pdf_forensics file1.pdf file2.pdf file3.pdf")
        print("  python -m pdf_forensics data/*.pdf --output report.md")
        sys.exit(1)
    
    # Parse arguments - separate files from options
    pdf_files = []
    output_file = "source_analysis_report.md"
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_file = args[i + 1]
            i += 2
        else:
            path = Path(args[i])
            if path.is_dir():
                pdf_files.extend(list(path.glob("*.pdf")))
            elif path.suffix.lower() == ".pdf" and path.exists():
                pdf_files.append(path)
            i += 1
    
    if not pdf_files:
        print("No PDF files found")
        sys.exit(1)
    
    # Check file sizes before processing
    for pdf_file in pdf_files:
        is_ok, error_msg = check_file_size(str(pdf_file))
        if not is_ok:
            print(f"⛔ Error: {error_msg}")
            sys.exit(1)
    
    print(f"Analyzing {len(pdf_files)} PDF files...")
    print()
    
    # Extract fingerprints
    fingerprints = []
    for pdf_file in pdf_files:
        print(f"  📄 {pdf_file.name}")
        fp = extract_source_fingerprint(str(pdf_file))
        fingerprints.append(fp)
        print(f"     → Source: {fp['source_id'].get('system', 'Unknown')} ({fp['source_hash']})")
    
    print()
    
    # Analyze similarity
    similarity = analyze_source_similarity(fingerprints)
    
    if "error" not in similarity:
        print(f"📊 Found {similarity['group_count']} unique source system(s)")
        print()
        
        for source_hash, files in similarity["source_groups"].items():
            fp = next(f for f in fingerprints if f["source_hash"] == source_hash)
            print(f"   🔹 {fp['source_id'].get('system', 'Unknown')}: {len(files)} document(s)")
        
        print()
    else:
        # Single file - create minimal similarity structure
        similarity = {
            "source_groups": {fingerprints[0]["source_hash"]: [fingerprints[0]["file"]]},
            "group_count": 1,
            "similarities": [],
        }
        print(f"📊 Analyzing 1 document (need 2+ for similarity comparison)")
        print()
    
    # Generate report
    report_path = generate_source_report(fingerprints, similarity, output_file)
    print(f"✅ Report saved to: {report_path}")


def main_verify_signature():
    """
    Main CLI entry point for PDF digital signature verification.
    
    Originally from verify_signature.py main() function.
    Extracts and verifies digital signatures from PDF documents.
    """
    # Import here to avoid circular dependencies
    from verify_signature import extract_signatures
    from pdf_forensics.reporting import generate_signature_report
    from pdf_forensics.signature import validate_signature as validate_signature_pyhanko
    
    if len(sys.argv) < 2:
        print("Usage: python verify_signature.py <pdf_file> [output.md]")
        print("\nVerifies digital signatures in PDF documents.")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    
    # Check file size before processing
    is_ok, error_msg = check_file_size(pdf_path)
    if not is_ok:
        print(f"⛔ Error: {error_msg}")
        sys.exit(1)
    
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    else:
        output_path = Path(pdf_path).stem + "_signature_report.md"
    
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
    
    if results["has_signatures"]:
        print(f"\n✅ Found {results['signature_count']} digital signature(s)")
        
        if validation_results.get("has_signatures"):
            if validation_results["signature_valid"] and validation_results["intact"]:
                print("✅ Signatures are cryptographically valid and document is intact")
            elif validation_results["signature_valid"]:
                print("⚠️ Signatures are valid but document may have been modified")
            else:
                print("❌ Signature validation failed")
    else:
        print("\n❌ No digital signatures found")
    
    report_path = generate_signature_report(results, output_path)
    print(f"📄 Report saved to: {report_path}")
    
    print("\n" + json.dumps(results, indent=2, default=str))


def main_compare_pdfs():
    """
    Main CLI entry point for comparing two PDF files.
    
    Originally from compare_pdfs.py main() function.
    Compares metadata and structure between two PDF documents.
    """
    # Import here to avoid circular dependencies
    from compare_pdfs import compare_pdfs
    from pdf_forensics.reporting import generate_markdown_report
    
    if len(sys.argv) < 3:
        print("Usage: python compare_pdfs.py <pdf1> <pdf2> [output.md]")
        print("\nCompares two PDF files and generates a forensic report.")
        sys.exit(1)
    
    pdf1 = sys.argv[1]
    pdf2 = sys.argv[2]
    
    # Check file sizes before processing
    for pdf_path in [pdf1, pdf2]:
        is_ok, error_msg = check_file_size(pdf_path)
        if not is_ok:
            print(f"⛔ Error: {error_msg}")
            sys.exit(1)
    
    output_file = sys.argv[3] if len(sys.argv) > 3 else "comparison_report.md"
    
    print(f"Analyzing: {pdf1}")
    print(f"Analyzing: {pdf2}")
    
    comparison = compare_pdfs(pdf1, pdf2)
    report = generate_markdown_report(comparison)
    
    # Write report
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"\n✅ Report generated: {output_file}")
    print(f"\n{comparison['verdict']}")
    
    if comparison["differences"]:
        print(f"\n📊 Found {len(comparison['differences'])} differences")
