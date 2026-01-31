#!/usr/bin/env python3
"""
PDF Comparison Tool - Compare metadata between two PDF files
Generates a markdown report highlighting differences and suspicious indicators
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

import fitz  # PyMuPDF
import pikepdf
from pypdf import PdfReader
import magic

from pdf_forensics.reporting import generate_markdown_report

def extract_metadata(pdf_path: str) -> dict:
    """Extract comprehensive metadata from a PDF file"""
    results = {
        "file": Path(pdf_path).name,
        "file_path": pdf_path,
        "metadata": {},
        "file_info": {},
        "suspicious_indicators": [],
    }
    
    path = Path(pdf_path)
    if not path.exists():
        results["error"] = "File not found"
        return results

    # File-level info
    stat = path.stat()
    results["file_info"] = {
        "size_bytes": stat.st_size,
        "size_human": _human_size(stat.st_size),
        "mime_type": magic.from_file(str(path), mime=True),
        "file_type": magic.from_file(str(path)),
        "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }

    # PyMuPDF analysis
    try:
        with fitz.open(pdf_path) as doc:
            meta = doc.metadata
            results["metadata"]["title"] = meta.get("title", "")
            results["metadata"]["author"] = meta.get("author", "")
            results["metadata"]["subject"] = meta.get("subject", "")
            results["metadata"]["keywords"] = meta.get("keywords", "")
            results["metadata"]["creator"] = meta.get("creator", "")
            results["metadata"]["producer"] = meta.get("producer", "")
            results["metadata"]["creation_date"] = meta.get("creationDate", "")
            results["metadata"]["modification_date"] = meta.get("modDate", "")
            results["file_info"]["page_count"] = doc.page_count
            results["file_info"]["is_encrypted"] = doc.is_encrypted
            results["file_info"]["pdf_version"] = meta.get("format", "")
    except Exception as e:
        results["metadata"]["error"] = str(e)

    # pikepdf for object count
    try:
        with pikepdf.open(pdf_path) as pdf:
            results["file_info"]["object_count"] = len(pdf.objects)
            results["file_info"]["pdf_version"] = f"{pdf.pdf_version}"
    except Exception as e:
        pass

    # Check suspicious indicators
    _check_suspicious(results)
    
    return results


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _check_suspicious(results: dict):
    """Check for suspicious patterns"""
    meta = results.get("metadata", {})
    indicators = results["suspicious_indicators"]
    
    producer = str(meta.get("producer", "")).lower()
    creator = str(meta.get("creator", "")).lower()
    
    # Online tools
    suspicious_tools = [
        "ilovepdf", "smallpdf", "pdf24", "sejda", "pdfcandy",
        "online2pdf", "sodapdf", "pdf2go", "cleverpdf",
        "microsoft print to pdf", "chrome", "firefox", "safari"
    ]
    
    for tool in suspicious_tools:
        if tool in producer or tool in creator:
            indicators.append(f"Processed with online/browser tool: {tool}")
    
    # Date mismatch
    if meta.get("creation_date") and meta.get("modification_date"):
        if meta["creation_date"] != meta["modification_date"]:
            indicators.append("Creation and modification dates differ")


def compare_pdfs(pdf1_path: str, pdf2_path: str) -> dict:
    """Compare two PDF files and identify differences"""
    meta1 = extract_metadata(pdf1_path)
    meta2 = extract_metadata(pdf2_path)
    
    comparison = {
        "analysis_time": datetime.now().isoformat(),
        "file1": meta1,
        "file2": meta2,
        "differences": [],
        "verdict": "",
    }
    
    # Compare file info
    for key in ["size_bytes", "page_count", "object_count", "pdf_version"]:
        val1 = meta1.get("file_info", {}).get(key)
        val2 = meta2.get("file_info", {}).get(key)
        if val1 != val2:
            comparison["differences"].append({
                "field": key,
                "file1": val1,
                "file2": val2,
            })
    
    # Compare metadata
    for key in ["title", "author", "subject", "creator", "producer", 
                "creation_date", "modification_date", "keywords"]:
        val1 = meta1.get("metadata", {}).get(key, "")
        val2 = meta2.get("metadata", {}).get(key, "")
        if val1 != val2:
            comparison["differences"].append({
                "field": key,
                "file1": val1,
                "file2": val2,
            })
    
    # Generate verdict
    if not comparison["differences"]:
        comparison["verdict"] = "✅ Files appear identical in metadata"
    else:
        all_suspicious = meta1["suspicious_indicators"] + meta2["suspicious_indicators"]
        if all_suspicious:
            comparison["verdict"] = "⚠️ SUSPICIOUS: Files differ and contain manipulation indicators"
        else:
            comparison["verdict"] = "📝 Files have metadata differences"
    
    return comparison


def main():
    import warnings
    warnings.warn(
        "Direct script execution is deprecated. Use 'python compare_pdfs.py <file1> <file2>' or import from pdf_forensics.cli",
        DeprecationWarning,
        stacklevel=2
    )
    from pdf_forensics.cli import main_compare_pdfs
    main_compare_pdfs()


def _deprecated_main():
    if len(sys.argv) < 3:
        print("Usage: python compare_pdfs.py <pdf1> <pdf2> [output.md]")
        print("\nCompares two PDF files and generates a forensic report.")
        sys.exit(1)
    
    pdf1 = sys.argv[1]
    pdf2 = sys.argv[2]
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


if __name__ == "__main__":
    main()
