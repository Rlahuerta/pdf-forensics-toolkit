#!/usr/bin/env python3
"""
PDF Source Identifier - Forensic tool to identify the source system of PDF documents
Groups documents by their origin and generates a source fingerprint
Enhanced with incremental update detection, embedded image analysis, and security indicators
"""

import sys
import json
import hashlib
import re
import math
import difflib
import tempfile
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

import fitz  # PyMuPDF
import pikepdf
from pypdf import PdfReader

from pdf_forensics.constants import (
    KNOWN_PRODUCERS, 
    SUSPICIOUS_PRODUCERS, 
    COMMON_PRODUCERS,
    INTEGRITY_SCORE_EXCELLENT_MIN,
    INTEGRITY_SCORE_GOOD_MIN,
    INTEGRITY_SCORE_QUESTIONABLE_MIN,
    TAMPERING_RISK_CRITICAL_MIN,
    TAMPERING_RISK_HIGH_MIN,
    TAMPERING_RISK_MEDIUM_MIN,
    SIMILARITY_SCORE_EXCELLENT_MIN,
    SIMILARITY_SCORE_GOOD_MIN,
    MAX_DIFF_LINES_TO_REPORT,
    MAX_DIFF_LINES_PREVIEW,
    MAX_SCORE,
)
from pdf_forensics.detection import _compare_library_metadata
from pdf_forensics.logging_config import get_logger
from pdf_forensics.scoring import _quantify_changes, _calculate_integrity_score, _calculate_similarity
from pdf_forensics.reporting import generate_source_report

# Initialize logger
logger = get_logger(__name__)

# Known producer/creator database for better identification (imported from pdf_forensics.constants)

def extract_source_fingerprint(pdf_path: str) -> Dict[str, Any]:
    """Extract a comprehensive source fingerprint from a PDF"""
    fingerprint = {
        "file": Path(pdf_path).name,
        "file_path": pdf_path,
        "software": {},
        "structure": {},
        "fonts": [],
        "streams": {},
        "resources": {},
        "page_layout": {},
        "xmp_namespaces": [],
        "naming_patterns": {},
        "source_hash": "",
        # New enhanced fields
        "incremental_updates": {},
        "security_indicators": {},
        "entropy": {},
        "embedded_content": {},
        "timeline": {},
        "integrity_score": 100,
    }
    
    path = Path(pdf_path)
    if not path.exists():
        fingerprint["error"] = "File not found"
        return fingerprint

    # Software identification
    try:
        with fitz.open(pdf_path) as doc:
            meta = doc.metadata
            fingerprint["software"] = {
                "creator": meta.get("creator", "") or "",
                "producer": meta.get("producer", "") or "",
                "creator_normalized": _normalize_software_name(meta.get("creator", "")),
                "producer_normalized": _normalize_software_name(meta.get("producer", "")),
            }
    except Exception as e:
        fingerprint["software"]["error"] = str(e)

    # Deep structure analysis with pikepdf
    try:
        with pikepdf.open(pdf_path) as pdf:
            # PDF version and object count
            fingerprint["structure"] = {
                "pdf_version": str(pdf.pdf_version),
                "object_count": len(pdf.objects),
                "page_count": len(pdf.pages),
            }
            
            # Object type distribution
            obj_types = defaultdict(int)
            for objnum in range(1, len(pdf.objects) + 1):
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Dictionary):
                        obj_type = str(obj.get('/Type', 'Dictionary'))
                        obj_types[obj_type] += 1
                    elif isinstance(obj, pikepdf.Stream):
                        obj_types['Stream'] += 1
                    elif isinstance(obj, pikepdf.Array):
                        obj_types['Array'] += 1
                    else:
                        obj_types['Other'] += 1
                except Exception as e:
                    logger.warning(f"Failed to extract object type for object {objnum}: {e}")
            fingerprint["structure"]["object_types"] = dict(obj_types)
            
            # Stream compression filters
            filters = defaultdict(int)
            for objnum in range(1, len(pdf.objects) + 1):
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Stream):
                        f = obj.get('/Filter')
                        if f:
                            if isinstance(f, pikepdf.Array):
                                for fitem in f:
                                    filters[str(fitem)] += 1
                            else:
                                filters[str(f)] += 1
                except Exception as e:
                    logger.warning(f"Failed to extract stream filters for object {objnum}: {e}")
            fingerprint["streams"] = {
                "filters": dict(filters),
                "filter_signature": "|".join(sorted(filters.keys())),
            }
            
            # XMP namespace analysis
            if pdf.Root.get('/Metadata'):
                try:
                    xmp = bytes(pdf.Root['/Metadata'].read_bytes()).decode('utf-8', errors='ignore')
                    namespaces = re.findall(r'xmlns:(\w+)="([^"]+)"', xmp)
                    fingerprint["xmp_namespaces"] = [{"prefix": ns, "uri": uri} for ns, uri in namespaces]
                    fingerprint["naming_patterns"]["xmp_namespace_signature"] = "|".join(sorted([uri for _, uri in namespaces]))
                except Exception as e:
                    logger.warning(f"Failed to parse XMP metadata: {e}")

            # Fonts and naming patterns
            fonts = set()
            has_subset_fonts = False
            for page in pdf.pages:
                try:
                    resources = page.get('/Resources')
                    if isinstance(resources, pikepdf.Object) and hasattr(resources, "get_object"):
                        try:
                            resources = resources.get_object()
                        except Exception:
                            pass
                    if isinstance(resources, pikepdf.Dictionary) and '/Font' in resources:
                        font_dict = resources['/Font']
                        if isinstance(font_dict, pikepdf.Object) and hasattr(font_dict, "get_object"):
                            try:
                                font_dict = font_dict.get_object()
                            except Exception:
                                pass
                        if isinstance(font_dict, pikepdf.Dictionary):
                            for font_key, font_ref in font_dict.items():
                                font_name = str(font_key)
                                try:
                                    font_obj = font_ref
                                    if isinstance(font_ref, pikepdf.Object) and hasattr(font_ref, "get_object"):
                                        try:
                                            font_obj = font_ref.get_object()
                                        except Exception:
                                            font_obj = font_ref
                                    if isinstance(font_obj, pikepdf.Dictionary):
                                        base_font = font_obj.get('/BaseFont')
                                        if base_font:
                                            font_name = str(base_font)
                                except Exception as e:
                                    logger.warning(f"Failed to parse font {font_key}: {e}")
                                fonts.add(font_name)
                                if '+' in font_name:
                                    has_subset_fonts = True
                except Exception as e:
                    logger.warning(f"Failed to extract fonts from page: {e}")
            fingerprint["fonts"] = sorted(fonts)
            fingerprint["naming_patterns"]["has_subset_fonts"] = has_subset_fonts

            has_acroform = '/AcroForm' in pdf.Root
            fingerprint["naming_patterns"]["has_acroform"] = has_acroform
            has_xfa = False
            if has_acroform:
                try:
                    acroform = pdf.Root['/AcroForm']
                    if isinstance(acroform, pikepdf.Dictionary) and '/XFA' in acroform:
                        has_xfa = True
                except Exception as e:
                    logger.warning(f"Failed to inspect AcroForm for XFA: {e}")
            fingerprint["naming_patterns"]["has_xfa"] = has_xfa

            # Page layout analysis
            page_sizes = defaultdict(int)
            for page in pdf.pages:
                try:
                    mediabox = page.MediaBox
                    if mediabox and len(mediabox) >= 4:
                        width = float(mediabox[2]) - float(mediabox[0])
                        height = float(mediabox[3]) - float(mediabox[1])
                        size_key = f"{round(width, 1)}x{round(height, 1)}"
                        page_sizes[size_key] += 1
                except Exception as e:
                    logger.warning(f"Failed to extract page size: {e}")
            fingerprint["page_layout"] = {
                "page_sizes": dict(page_sizes),
                "size_signature": "|".join(sorted(page_sizes.keys())),
            }

    except Exception as e:
        fingerprint["structure"]["error"] = str(e)

    # Additional analysis with fitz and detection modules
    try:
        from pdf_forensics.detection import (
            _detect_incremental_updates,
            _detect_tampering_indicators,
            _detect_security_indicators,
        )
    except Exception as e:
        fingerprint["error"] = str(e)
        return fingerprint

    try:
        fingerprint["incremental_updates"] = _detect_incremental_updates(pdf_path)
    except Exception as e:
        fingerprint["incremental_updates"] = {"error": str(e)}

    try:
        fingerprint["tampering"] = _detect_tampering_indicators(pdf_path)
    except Exception as e:
        fingerprint["tampering"] = {"error": str(e)}

    try:
        fingerprint["security_indicators"] = _detect_security_indicators(pdf_path)
    except Exception as e:
        fingerprint["security_indicators"] = {"error": str(e)}

    fingerprint["revision_content"] = _extract_revision_content(pdf_path)
    fingerprint["entropy"] = _analyze_entropy(pdf_path)
    fingerprint["embedded_content"] = _analyze_embedded_content(pdf_path)
    fingerprint["timeline"] = _extract_timeline(pdf_path, fingerprint)

    fingerprint["source_hash"] = _generate_source_hash(fingerprint)
    fingerprint["source_id"] = _classify_source(fingerprint)
    fingerprint["integrity_score"] = _calculate_integrity_score(fingerprint)

    return fingerprint


def _extract_revision_content(pdf_path: str) -> Dict[str, Any]:
    """
    Extract content from different revisions of a PDF to detect text changes.
    PDFs with incremental updates may contain previous versions.
    """
    result = {
        "has_revisions": False,
        "revision_count": 0,
        "revisions": [],
        "content_changes": [],
        "additions": [],
        "deletions": [],
        "summary": "",
    }
    
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
        
        # Find all %%EOF markers to identify revision boundaries
        eof_positions = []
        pos = 0
        while True:
            idx = content.find(b'%%EOF', pos)
            if idx == -1:
                break
            # Find the actual end (after newlines)
            end_pos = idx + 5
            while end_pos < len(content) and content[end_pos:end_pos+1] in (b'\r', b'\n'):
                end_pos += 1
            eof_positions.append(end_pos)
            pos = end_pos
        
        if len(eof_positions) <= 1:
            result["summary"] = "No incremental updates found - document appears to be single revision"
            return result
        
        result["has_revisions"] = True
        result["revision_count"] = len(eof_positions)
        
        # Extract text from each revision
        revision_texts = []
        
        for rev_num, eof_pos in enumerate(eof_positions):
            tmp_path = None
            try:
                # Create a temporary file with just this revision
                revision_data = content[:eof_pos]
                
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
                    tmp_path = tmp.name
                    tmp.write(revision_data)
                
                # Extract text from this revision
                with fitz.open(tmp_path) as doc:
                    text_content = []
                    for page_num in range(len(doc)):
                        page = doc[page_num]
                        text = page.get_text().strip()
                        if text:
                            text_content.append(f"[Page {page_num + 1}]\n{text}")
                    
                    full_text = "\n\n".join(text_content)
                    revision_texts.append({
                        "revision": rev_num + 1,
                        "size": eof_pos,
                        "page_count": len(doc),
                        "text": full_text,
                        "char_count": len(full_text),
                    })

            except Exception as e:
                revision_texts.append({
                    "revision": rev_num + 1,
                    "size": eof_pos if 'eof_pos' in locals() else 0,
                    "error": str(e),
                    "text": "",
                })
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        
        result["revisions"] = revision_texts
        
        # Compare consecutive revisions to find changes
        for i in range(1, len(revision_texts)):
            prev_rev = revision_texts[i - 1]
            curr_rev = revision_texts[i]
            
            if prev_rev.get("error") or curr_rev.get("error"):
                continue
            
            prev_text = prev_rev.get("text", "")
            curr_text = curr_rev.get("text", "")
            
            if prev_text == curr_text:
                continue
            
            # Generate diff
            diff_result = _generate_text_diff(prev_text, curr_text, prev_rev["revision"], curr_rev["revision"])
            
            if diff_result["has_changes"]:
                result["content_changes"].append(diff_result)
                result["additions"].extend(diff_result.get("additions", []))
                result["deletions"].extend(diff_result.get("deletions", []))
        
        # Generate summary
        if result["content_changes"]:
            total_additions = len(result["additions"])
            total_deletions = len(result["deletions"])
            result["summary"] = f"Found {len(result['content_changes'])} revision(s) with content changes: {total_additions} addition(s), {total_deletions} deletion(s)"
        else:
            result["summary"] = f"Document has {result['revision_count']} revision(s) but no text content changes detected"
            
    except Exception as e:
        result["error"] = str(e)
        result["summary"] = f"Error analyzing revisions: {str(e)}"
    
    return result


def _generate_text_diff(text1: str, text2: str, rev1: int, rev2: int) -> Dict[str, Any]:
    """Generate a detailed diff between two text versions"""
    result = {
        "from_revision": rev1,
        "to_revision": rev2,
        "has_changes": False,
        "additions": [],
        "deletions": [],
        "diff_lines": [],
    }
    
    # Split into lines for comparison
    lines1 = text1.splitlines()
    lines2 = text2.splitlines()
    
    # Use difflib to find differences
    differ = difflib.unified_diff(lines1, lines2, lineterm='', n=1)
    diff_lines = list(differ)
    
    if len(diff_lines) > 4:  # Has actual changes (skip header lines)
        result["has_changes"] = True
        
        for line in diff_lines[2:]:  # Skip the --- and +++ header lines
            if line.startswith('+') and not line.startswith('+++'):
                clean_line = line[1:].strip()
                if clean_line and len(clean_line) > 2:  # Ignore trivial changes
                    result["additions"].append({
                        "text": clean_line[:200] + ("..." if len(clean_line) > 200 else ""),
                        "revision": rev2,
                    })
            elif line.startswith('-') and not line.startswith('---'):
                clean_line = line[1:].strip()
                if clean_line and len(clean_line) > 2:  # Ignore trivial changes
                    result["deletions"].append({
                        "text": clean_line[:200] + ("..." if len(clean_line) > 200 else ""),
                        "revision": rev1,
                    })
        
        # Store a sample of diff lines for the report
        result["diff_lines"] = diff_lines[:MAX_DIFF_LINES_TO_REPORT]
    
    return result


def _analyze_entropy(pdf_path: str) -> Dict[str, Any]:
    """Analyze entropy of streams to detect obfuscation or encryption"""
    result = {
        "average_entropy": 0.0,
        "max_entropy": 0.0,
        "high_entropy_count": 0,
        "total_streams": 0,
        "entropy_distribution": {},
        "suspicious": False,
    }
    
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        size = len(data)
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        for count in freq.values():
            p = count / size
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    try:
        with pikepdf.open(pdf_path) as pdf:
            entropies = []
            
            for objnum in range(1, min(len(pdf.objects) + 1, 500)):  # Limit scan
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Stream):
                        try:
                            # Skip very large streams to prevent OOM
                            # (checking uncompressed length is hard without reading, but we can catch errors)
                            data = bytes(obj.read_bytes())
                            
                            # Limit analysis to first 64KB
                            if len(data) > 64 * 1024:
                                data = data[:64 * 1024]
                                
                            if len(data) > 100:  # Only analyze meaningful streams
                                entropy = calculate_entropy(data)
                                entropies.append(entropy)
                                if entropy > 7.5:  # High entropy threshold
                                    result["high_entropy_count"] += 1
                        except Exception:
                            pass
                except Exception:
                    pass
            
            if entropies:
                result["total_streams"] = len(entropies)
                result["average_entropy"] = round(sum(entropies) / len(entropies), 2)
                result["max_entropy"] = round(max(entropies), 2)
                
                # Categorize entropy distribution
                low = sum(1 for e in entropies if e < 4)
                medium = sum(1 for e in entropies if 4 <= e < 7)
                high = sum(1 for e in entropies if e >= 7)
                result["entropy_distribution"] = {"low": low, "medium": medium, "high": high}
                
                # Flag suspicious if too many high-entropy streams
                if result["high_entropy_count"] > len(entropies) * 0.5:
                    result["suspicious"] = True
                    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _analyze_embedded_content(pdf_path: str) -> Dict[str, Any]:
    """Analyze embedded images and files"""
    result = {
        "image_count": 0,
        "image_formats": [],
        "embedded_file_count": 0,
        "embedded_files": [],
        "total_embedded_size": 0,
        "images_with_exif": 0,
    }
    
    try:
        with fitz.open(pdf_path) as doc:
            
            image_formats = defaultdict(int)
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                image_list = page.get_images(full=True)
                
                for img in image_list:
                    result["image_count"] += 1
                    xref = img[0]
                    
                    try:
                        base_image = doc.extract_image(xref)
                        if base_image:
                            ext = base_image.get("ext", "unknown")
                            image_formats[ext] += 1
                            result["total_embedded_size"] += len(base_image.get("image", b""))
                    except Exception:
                        pass
            
            result["image_formats"] = [{"format": k, "count": v} for k, v in image_formats.items()]
            
            # Check for embedded files
            try:
                if doc.embfile_count() > 0:
                    result["embedded_file_count"] = doc.embfile_count()
                    for i in range(doc.embfile_count()):
                        info = doc.embfile_info(i)
                        result["embedded_files"].append({
                            "name": info.get("name", "unknown"),
                            "size": info.get("size", 0),
                        })
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _parse_pdf_date(date_str: str) -> str:
    """Parse and normalize PDF date string to ISO format (YYYY-MM-DDThh:mm:ss)"""
    if not date_str:
        return ""
    
    try:
        # Clean up string
        clean = date_str.replace("'", "").replace("Z", "+0000")
        if clean.startswith("D:"):
            clean = clean[2:]
            
        # Regex for YYYYMMDDHHmmSS...
        match = re.match(r'^(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?', clean)
        if match:
            groups = match.groups()
            year = groups[0]
            month = groups[1]
            day = groups[2]
            hour = groups[3] or "00"
            minute = groups[4] or "00"
            second = groups[5] or "00"
            return f"{year}-{month}-{day}T{hour}:{minute}:{second}"
            
        # Regex for ISO-like (XMP)
        match = re.search(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', date_str)
        if match:
             return match.group(0)
             
    except Exception:
        pass
        
    return date_str


def _extract_timeline(pdf_path: str, fingerprint: Dict) -> Dict[str, Any]:
    """Extract all dates and build a timeline"""
    result = {
        "creation_date": "",
        "modification_date": "",
        "all_dates": [],
        "date_anomalies": [],
    }
    
    try:
        with fitz.open(pdf_path) as doc:
            meta = doc.metadata
            
            creation = meta.get("creationDate", "")
            modification = meta.get("modDate", "")
            
            result["creation_date"] = creation
            result["modification_date"] = modification
            
            dates = []
            if creation:
                dates.append({"source": "creation_date", "value": creation, "normalized": _parse_pdf_date(creation)})
            if modification:
                dates.append({"source": "modification_date", "value": modification, "normalized": _parse_pdf_date(modification)})
            
            # Parse XMP for additional dates
            try:
                with pikepdf.open(pdf_path) as pdf:
                    if pdf.Root.get('/Metadata'):
                        xmp = bytes(pdf.Root['/Metadata'].read_bytes()).decode('utf-8', errors='ignore')
                        
                        # Find all date patterns in XMP
                        xmp_dates = re.findall(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', xmp)
                        for d in xmp_dates:
                            # Only add if we haven't seen this exact normalized date yet
                            normalized = _parse_pdf_date(d)
                            seen_normalized = [x.get("normalized") for x in dates]
                            if normalized and normalized not in seen_normalized:
                                dates.append({"source": "xmp_metadata", "value": d, "normalized": normalized})
            except Exception:
                pass
            
            result["all_dates"] = dates
            
            # Check for anomalies
            if creation and modification:
                norm_creation = _parse_pdf_date(creation)
                norm_mod = _parse_pdf_date(modification)
                
                if norm_creation and norm_mod:
                    if norm_mod < norm_creation:
                        result["date_anomalies"].append(f"Modification date ({norm_mod}) is earlier than creation date ({norm_creation})")
                    elif norm_mod != norm_creation:
                        # Only note distinct modification as a fact, not necessarily an anomaly in the 'bad' sense
                        # but keeping structure consistent with original intent
                        pass
    except Exception as e:
        result["error"] = str(e)
    
    return result





def _normalize_software_name(name: str) -> str:
    """Normalize software name for comparison (remove version numbers)"""
    if not name:
        return ""
    # Remove version numbers
    normalized = re.sub(r'\s*[\d\.]+(-preview-\d+)?', '', name)
    # Remove URLs
    normalized = re.sub(r'\([^)]*\)', '', normalized)
    return normalized.strip().lower()


def _generate_source_hash(fingerprint: Dict) -> str:
    """Generate a hash that identifies the source system"""
    # Components that identify the source (not the specific document)
    components = [
        fingerprint["software"].get("creator_normalized", ""),
        fingerprint["software"].get("producer_normalized", ""),
        fingerprint["structure"].get("pdf_version", ""),
        fingerprint["streams"].get("filter_signature", ""),
        fingerprint["page_layout"].get("size_signature", ""),
        str(fingerprint["naming_patterns"].get("has_xfa", False)),
        str(fingerprint["naming_patterns"].get("has_acroform", False)),
    ]
    
    # Add font base names (without subset prefixes)
    base_fonts = []
    for font in fingerprint.get("fonts", []):
        if '+' in font:
            base_fonts.append(font.split('+')[1])
        else:
            base_fonts.append(font)
    components.append("|".join(sorted(set(base_fonts))))
    
    source_string = "::".join(components)
    return hashlib.sha256(source_string.encode()).hexdigest()[:16]


def _classify_source(fingerprint: Dict) -> Dict[str, Any]:
    """Classify the likely source system based on fingerprint"""
    creator = fingerprint["software"].get("creator", "").lower()
    producer = fingerprint["software"].get("producer", "").lower()
    
    classification = {
        "type": "unknown",
        "system": "Unknown",
        "confidence": "low",
        "details": [],
    }
    
    # PDFsharp detection
    if "pdfsharp" in creator or "pdfsharp" in producer:
        classification["type"] = "dynamic_generation"
        classification["system"] = "PDFsharp (.NET)"
        classification["confidence"] = "high"
        classification["details"] = [
            ".NET library for programmatic PDF generation",
            "Commonly used in ASP.NET web applications",
            "Documents generated on-demand from templates",
        ]
        # Extract version
        version_match = re.search(r'pdfsharp\s*([\d\.\-\w]+)', creator + producer, re.IGNORECASE)
        if version_match:
            classification["version"] = version_match.group(1)
    
    # Adobe Experience Manager
    elif "adobe experience manager" in producer or "aem" in producer:
        classification["type"] = "enterprise_forms"
        classification["system"] = "Adobe Experience Manager Forms"
        classification["confidence"] = "high"
        classification["details"] = [
            "Enterprise document generation platform",
            "Uses Adobe Designer for form templates",
            "Common in insurance, banking, government",
        ]
        if "designer" in creator:
            version_match = re.search(r'designer\s*([\d\.]+)', creator, re.IGNORECASE)
            if version_match:
                classification["template_version"] = f"Designer {version_match.group(1)}"
    
    # iText
    elif "itext" in creator or "itext" in producer:
        classification["type"] = "dynamic_generation"
        classification["system"] = "iText (Java)"
        classification["confidence"] = "high"
        classification["details"] = [
            "Java library for PDF generation",
            "Common in Java web applications",
        ]
    
    # wkhtmltopdf
    elif "wkhtmltopdf" in creator or "wkhtmltopdf" in producer:
        classification["type"] = "html_to_pdf"
        classification["system"] = "wkhtmltopdf"
        classification["confidence"] = "high"
        classification["details"] = [
            "Converts HTML/CSS to PDF",
            "Uses WebKit rendering engine",
        ]
    
    # Chrome/Chromium
    elif "chrome" in creator or "chromium" in producer:
        classification["type"] = "browser_print"
        classification["system"] = "Chrome/Chromium Print"
        classification["confidence"] = "high"
        classification["details"] = [
            "Browser print-to-PDF functionality",
            "May indicate manual document creation",
        ]
    
    # Microsoft
    elif "microsoft" in creator or "microsoft" in producer:
        classification["type"] = "office_export"
        classification["system"] = "Microsoft Office"
        classification["confidence"] = "medium"
        classification["details"] = [
            "Exported from Microsoft Office application",
        ]
    
    # Adobe Acrobat
    elif "acrobat" in creator or "acrobat" in producer:
        classification["type"] = "desktop_creation"
        classification["system"] = "Adobe Acrobat"
        classification["confidence"] = "high"
        classification["details"] = [
            "Created or edited with Adobe Acrobat",
        ]
    
    return classification


def analyze_source_similarity(fingerprints: List[Dict]) -> Dict[str, Any]:
    """Analyze similarity between multiple PDF fingerprints"""
    if len(fingerprints) < 2:
        return {"error": "Need at least 2 documents to compare"}
    
    # Group by source hash
    groups = defaultdict(list)
    for fp in fingerprints:
        groups[fp["source_hash"]].append(fp["file"])
    
    # Calculate pairwise similarity
    similarities = []
    for i, fp1 in enumerate(fingerprints):
        for fp2 in fingerprints[i+1:]:
            score = _calculate_similarity(fp1, fp2)
            similarities.append({
                "file1": fp1["file"],
                "file2": fp2["file"],
                "score": score,
                "same_source": fp1["source_hash"] == fp2["source_hash"],
            })
    
    return {
        "source_groups": {k: v for k, v in groups.items()},
        "group_count": len(groups),
        "similarities": similarities,
    }




    # Comprehensive introduction for legal professionals
    report.append("## 📖 How to Read This Report")
    report.append("")
    report.append("This report provides a forensic analysis of PDF documents to help determine their authenticity and integrity. It is designed to be understood by legal professionals, not just technical experts.")
    report.append("")
    
    report.append("### Key Terms Explained")
    report.append("")
    
    # Integrity Score explanation
    report.append("#### 🛡️ Integrity Score (0-100)")
    report.append("")
    report.append("The **Integrity Score** measures how trustworthy a document appears based on its internal structure and metadata. Think of it like a health check for the document.")
    report.append("")
    report.append("| Score | Meaning | Recommended Action |")
    report.append("|:-----:|---------|-------------------|")
    report.append("| 🟢 **90-100** | **Excellent** - Document shows no signs of manipulation | Can be used with confidence |")
    report.append("| 🟡 **70-89** | **Good with concerns** - Minor anomalies detected | Review the specific concerns noted |")
    report.append("| 🟠 **50-69** | **Questionable** - Multiple warning signs present | Request original from source |")
    report.append("| 🔴 **0-49** | **Unreliable** - Strong evidence of tampering | Do not rely on this document |")
    report.append("")
    report.append("*A lower score does not prove fraud, but indicates the document requires additional verification.*")
    report.append("")
    
    # Tampering Risk Score explanation
    report.append("#### ⚠️ Tampering Risk Score (0-100)")
    report.append("")
    report.append("The **Tampering Risk Score** specifically measures indicators that the document may have been altered after its original creation. This is different from the Integrity Score because it focuses on *changes* rather than overall quality.")
    report.append("")
    report.append("| Score | Risk Level | What This Means |")
    report.append("|:-----:|:----------:|-----------------|")
    report.append("| **0** | ✅ None | No evidence of post-creation changes |")
    report.append("| **1-20** | 🔍 Low | Minor technical artifacts (often normal) |")
    report.append("| **21-40** | ⚠️ Medium | Document shows signs of editing or processing |")
    report.append("| **41-60** | 🔴 High | Significant evidence of modification |")
    report.append("| **61-100** | ⛔ Critical | Strong indicators of tampering or forgery |")
    report.append("")
    report.append("*A high tampering risk means the document was likely changed after it was first created. This could be legitimate (e.g., adding a signature) or suspicious (e.g., altering amounts or dates).*")
    report.append("")
    
    # Common Tampering Indicators explanation
    report.append("#### 🔍 Common Tampering Indicators")
    report.append("")
    report.append("When analyzing a document, we look for these signs of potential manipulation:")
    report.append("")
    report.append("| Indicator | What It Means | Why It Matters |")
    report.append("|-----------|---------------|----------------|")
    report.append("| **Orphan Objects** | Leftover data fragments inside the PDF | May contain deleted or replaced content |")
    report.append("| **Hidden Layers** | Content that exists but isn't normally visible | Could show different information when printed |")
    report.append("| **Incremental Updates** | The document was saved multiple times | Each save could represent a change to content |")
    report.append("| **Document ID Mismatch** | Internal identifiers don't match | Indicates the file was modified after creation |")
    report.append("| **Metadata Inconsistencies** | Conflicting information about creation | Suggests dates or authorship may be falsified |")
    report.append("| **Structural Anomalies** | Unusual internal file organization | May indicate use of editing tools |")
    report.append("")
    
    # Content Change Detection explanation
    report.append("#### 📝 Content Change Detection")
    report.append("")
    report.append("When a PDF has been modified through incremental updates, we can often **recover and compare previous versions** to show exactly what text was added or removed.")
    report.append("")
    report.append("- **➕ Text Added** - New text that appeared in a later revision")
    report.append("- **➖ Text Removed** - Text that existed in an earlier revision but was deleted")
    report.append("")
    report.append("*This is like having a \"track changes\" view of the document's history. If someone altered an invoice amount or contract term, the original value may still be recoverable.*")
    report.append("")
    
    # Generation Pipeline explanation
    report.append("#### 🏭 Generation Pipeline")
    report.append("")
    report.append("The **Generation Pipeline** identifies the software system that created the PDF. This is like identifying the \"factory\" that produced the document.")
    report.append("")
    report.append("**Why this matters:** If someone claims a document came from a bank's official system, but the pipeline shows it was created with consumer software like Microsoft Word, this raises questions about authenticity.")
    report.append("")
    report.append("Documents from the same source (e.g., the same insurance company portal) will have matching **Pipeline Fingerprints** - unique identifiers that link them to the same creation system.")
    report.append("")
    
    # How to use this report
    report.append("### How to Use This Report")
    report.append("")
    report.append("1. **Start with the Executive Summary** - Check if any documents are flagged as potentially compromised")
    report.append("2. **Review the Quick Reference Table** - Identify which documents need closer examination")
    report.append("3. **Examine flagged documents** - Read the detailed analysis for any document with warnings")
    report.append("4. **Follow recommendations** - Each flagged document includes specific next steps")
    report.append("5. **Consider the context** - Technical anomalies alone don't prove fraud; they indicate where to investigate further")
    report.append("")
    
    report.append("### Important Limitations")
    report.append("")
    report.append("- This analysis examines the **digital structure** of PDF files, not the truthfulness of their content")
    report.append("- A clean report does not guarantee a document is genuine - content could still be false")
    report.append("- Some legitimate documents may show warning signs due to normal business processes")
    report.append("- This report should be one part of a broader authenticity investigation")
    report.append("")
    report.append("---")
    report.append("")
    
    # Executive Summary with overview table
    report.append("## 📊 Executive Summary")
    report.append("")
    
    # Count modified and compromised documents
    modified_count = sum(1 for fp in fingerprints if fp.get("incremental_updates", {}).get("was_modified", False))
    compromised_count = sum(1 for fp in fingerprints if fp.get("tampering", {}).get("is_compromised", False))
    
    report.append(f"| Metric | Value |")
    report.append(f"|--------|-------|")
    report.append(f"| **Documents Analyzed** | {len(fingerprints)} |")
    report.append(f"| **Unique Pipelines Found** | {similarity['group_count']} |")
    report.append(f"| **Modified Documents** | {modified_count} |")
    report.append(f"| **Potentially Compromised** | {compromised_count} |")
    report.append(f"| **Original/Clean Documents** | {len(fingerprints) - modified_count} |")
    report.append("")
    
    # Alert banner if any documents are compromised
    if compromised_count > 0:
        report.append("### ⛔ SECURITY ALERT")
        report.append("")
        report.append(f"**{compromised_count} document(s) show signs of tampering or compromise.**")
        report.append("")
        report.append("Review the detailed analysis below before trusting these documents.")
        report.append("")
    
    # Quick reference table with modification and integrity status
    report.append("### Quick Reference")
    report.append("")
    report.append("| Document | System | Integrity | Tampering Risk |")
    report.append("|----------|--------|:---------:|:--------------:|")
    for fp in fingerprints:
        source_id = fp.get("source_id", {})
        tampering = fp.get("tampering", {})
        integrity_score = fp.get("integrity_score", 100)
        
        # Integrity icon
        if integrity_score >= INTEGRITY_SCORE_EXCELLENT_MIN:
            integrity_display = f"🟢 {integrity_score}"
        elif integrity_score >= INTEGRITY_SCORE_GOOD_MIN:
            integrity_display = f"🟡 {integrity_score}"
        elif integrity_score >= INTEGRITY_SCORE_QUESTIONABLE_MIN:
            integrity_display = f"🟠 {integrity_score}"
        else:
            integrity_display = f"🔴 {integrity_score}"
        
        # Tampering risk
        risk_score = tampering.get("risk_score", 0)
        if tampering.get("is_compromised"):
            confidence = tampering.get("compromise_confidence", "low")
            if confidence == "high":
                risk_display = f"⛔ HIGH ({risk_score})"
            else:
                risk_display = f"⚠️ MEDIUM ({risk_score})"
        elif risk_score > 0:
            risk_display = f"🔍 Low ({risk_score})"
        else:
            risk_display = "✅ None"
        
        report.append(f"| `{fp['file'][:28]}` | {source_id.get('system', 'Unknown')[:20]} | {integrity_display} | {risk_display} |")
    report.append("")
    
    # Individual Document Analysis
    report.append("---")
    report.append("")
    report.append("## 📄 Individual Document Analysis")
    report.append("")
    
    for i, fp in enumerate(fingerprints, 1):
        source_id = fp.get("source_id", {})
        
        report.append(f"### Document {i}: `{fp['file']}`")
        report.append("")
        
        # Generation Pipeline Table
        report.append("#### Generation Pipeline")
        report.append("")
        report.append("| Step | Component | Value |")
        report.append("|:----:|-----------|-------|")
        report.append(f"| 1 | **Software/Creator** | `{fp['software'].get('creator', 'N/A')}` |")
        report.append(f"| 2 | **Producer Engine** | `{fp['software'].get('producer', 'N/A')}` |")
        report.append(f"| 3 | **PDF Version** | `{fp['structure'].get('pdf_version', 'N/A')}` |")
        report.append(f"| 4 | **Compression Method** | `{fp['streams'].get('filter_signature', 'None') or 'None'}` |")
        report.append(f"| 5 | **Page Template** | `{fp['page_layout'].get('size_signature', 'N/A')}` |")
        
        # Font summary
        fonts = fp.get("fonts", [])
        if fonts:
            font_summary = ", ".join(fonts[:3])
            if len(fonts) > 3:
                font_summary += f" (+{len(fonts)-3} more)"
            report.append(f"| 6 | **Font Set** | `{font_summary}` |")
        else:
            report.append(f"| 6 | **Font Set** | None embedded |")
        
        report.append("")
        
        # Pipeline Fingerprint
        report.append("#### Pipeline Fingerprint")
        report.append("")
        report.append(f"```")
        report.append(f"{fp['source_hash']}")
        report.append(f"```")
        report.append("")
        report.append(f"**Identified System:** {source_id.get('system', 'Unknown')}")
        report.append(f"**System Type:** {source_id.get('type', 'unknown')}")
        report.append(f"**Confidence:** {source_id.get('confidence', 'low')}")
        report.append("")
        
        # Integrity Score
        integrity_score = fp.get("integrity_score", 100)
        if integrity_score >= INTEGRITY_SCORE_EXCELLENT_MIN:
            integrity_icon = "🟢"
        elif integrity_score >= INTEGRITY_SCORE_GOOD_MIN:
            integrity_icon = "🟡"
        else:
            integrity_icon = "🔴"
        report.append(f"**Integrity Score:** {integrity_icon} **{integrity_score}/100**")
        report.append("")
        
        # Modification Status - Always show this prominently
        incremental = fp.get("incremental_updates", {})
        was_modified = incremental.get("was_modified", False)
        
        report.append("#### 📝 Document Modification Status")
        report.append("")
        if was_modified:
            # Get change metrics
            change_metrics = incremental.get("change_metrics", {})
            mod_score = change_metrics.get("modification_score", 0)
            severity = change_metrics.get("severity", "unknown")
            
            # Severity icons
            severity_icons = {
                "none": "🟢",
                "minor": "🟡",
                "moderate": "🟠",
                "significant": "🔴",
                "major": "⛔",
            }
            severity_icon = severity_icons.get(severity, "❓")
            
            report.append(f"⚠️ **Status: MODIFIED** - Document was changed after initial creation")
            report.append("")
            report.append(f"**Modification Score:** {severity_icon} **{mod_score}/100** ({severity.upper()})")
            report.append("")
            
            # Change quantification table
            if change_metrics.get("bytes_added", 0) > 0 or change_metrics.get("change_types"):
                report.append("**Change Quantification:**")
                report.append("")
                report.append("| Metric | Value |")
                report.append("|--------|-------|")
                
                if change_metrics.get("original_size"):
                    report.append(f"| Original Size | {change_metrics['original_size']:,} bytes |")
                if change_metrics.get("final_size"):
                    report.append(f"| Final Size | {change_metrics['final_size']:,} bytes |")
                if change_metrics.get("bytes_added", 0) > 0:
                    report.append(f"| Bytes Added | **{change_metrics['bytes_added']:,}** bytes |")
                if change_metrics.get("size_increase_percent", 0) > 0:
                    report.append(f"| Size Increase | **{change_metrics['size_increase_percent']}%** |")
                if change_metrics.get("annotation_count", 0) > 0:
                    report.append(f"| Annotations | {change_metrics['annotation_count']} |")
                if change_metrics.get("form_field_count", 0) > 0:
                    report.append(f"| Form Fields | {change_metrics['form_field_count']} |")
                report.append("")
                
                # Revision breakdown
                if change_metrics.get("revision_sizes"):
                    report.append("**Revision History:**")
                    report.append("")
                    report.append("| Revision | Size | Cumulative |")
                    report.append("|:--------:|-----:|----------:|")
                    for rev in change_metrics["revision_sizes"]:
                        report.append(f"| {rev['revision']} | {rev['size']:,} bytes | {rev['cumulative']:,} bytes |")
                    report.append("")
            
            # Change types summary
            if change_metrics.get("change_types"):
                report.append("**Types of Changes Detected:**")
                for change_type in change_metrics["change_types"]:
                    report.append(f"- {change_type}")
                report.append("")
            
            # Evidence
            if incremental.get("modification_indicators"):
                report.append("**Evidence of modification:**")
                for indicator in incremental["modification_indicators"]:
                    report.append(f"- {indicator}")
                report.append("")
            if incremental.get("creation_date") and incremental.get("modification_date"):
                report.append(f"- **Created:** `{incremental.get('creation_date')}`")
                report.append(f"- **Modified:** `{incremental.get('modification_date')}`")
                report.append("")
            if not incremental.get("original_id_match", True):
                report.append(f"- **Original ID:** `{incremental.get('original_id', 'N/A')[:16]}...`")
                report.append(f"- **Current ID:** `{incremental.get('current_id', 'N/A')[:16]}...`")
                report.append("")
        else:
            report.append("✅ **Status: ORIGINAL** - No modification detected")
            report.append("")
            report.append(f"> {incremental.get('modification_summary', 'Document appears to be in its original state')}")
            report.append("")
        
        # Tampering/Compromise Analysis Section
        tampering = fp.get("tampering", {})
        if tampering.get("is_compromised") or tampering.get("risk_score", 0) > 0:
            if tampering.get("is_compromised"):
                confidence = tampering.get("compromise_confidence", "low")
                if confidence == "high":
                    report.append("#### ⛔ DOCUMENT COMPROMISE DETECTED")
                else:
                    report.append("#### ⚠️ Potential Document Compromise")
            else:
                report.append("#### 🔍 Tampering Analysis")
            report.append("")
            
            risk_score = tampering.get("risk_score", 0)
            if risk_score >= TAMPERING_RISK_CRITICAL_MIN:
                risk_icon = "⛔"
            elif risk_score >= TAMPERING_RISK_HIGH_MIN:
                risk_icon = "🔴"
            elif risk_score >= TAMPERING_RISK_MEDIUM_MIN:
                risk_icon = "🟠"
            else:
                risk_icon = "🟡"
            
            report.append(f"**Tampering Risk Score:** {risk_icon} **{risk_score}/100**")
            report.append("")
            
            # Indicators
            if tampering.get("indicators"):
                report.append("**Tampering Indicators:**")
                for indicator in tampering["indicators"]:
                    report.append(f"- ⚠️ {indicator}")
                report.append("")
            
            # Structural anomalies
            if tampering.get("structural_anomalies"):
                report.append("**Structural Anomalies:**")
                for anomaly in tampering["structural_anomalies"][:5]:
                    report.append(f"- {anomaly}")
                report.append("")
            
            # Hidden content
            if tampering.get("hidden_content"):
                report.append("**Hidden Content Detected:**")
                for hidden in tampering["hidden_content"][:5]:
                    report.append(f"- {hidden}")
                report.append("")
            
            # Orphan objects
            if tampering.get("orphan_objects"):
                report.append(f"**Orphan Objects:** {len(tampering['orphan_objects'])} unreferenced object(s)")
                if len(tampering["orphan_objects"]) <= 5:
                    for orphan in tampering["orphan_objects"]:
                        report.append(f"- {orphan}")
                report.append("")
            
            # Metadata inconsistencies
            if tampering.get("metadata_inconsistencies"):
                report.append("**Metadata Inconsistencies:**")
                for inconsistency in tampering["metadata_inconsistencies"]:
                    report.append(f"- ⚠️ {inconsistency}")
                report.append("")
            
            # Shadow attack risk
            if tampering.get("shadow_attack_risk"):
                report.append("> ⛔ **Shadow Attack Risk:** Document structure could allow hidden content overlay")
                report.append("")
            
            # Recommendations
            if tampering.get("recommendations"):
                report.append("**Recommendations:**")
                for rec in tampering["recommendations"]:
                    report.append(f"- {rec}")
                report.append("")
        
        # Security Indicators Section
        security = fp.get("security_indicators", {})
        if security.get("risk_level", "low") != "low" or security.get("has_javascript") or security.get("has_launch_action"):
            report.append("#### ⚠️ Security Indicators")
            report.append("")
            risk_level = security.get("risk_level", "low")
            risk_icon = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
            report.append(f"**Risk Level:** {risk_icon} **{risk_level.upper()}**")
            report.append("")
            if security.get("suspicious_elements"):
                for elem in security["suspicious_elements"]:
                    report.append(f"- ⚠️ {elem}")
            if security.get("urls_found"):
                report.append("")
                report.append("**URLs Found:**")
                for url in security["urls_found"][:5]:  # Limit to first 5
                    report.append(f"- `{url}`")
            report.append("")
        
        # Detailed Modification History (only if modified)
        if incremental.get("has_incremental_updates"):
            report.append("#### 🔍 Incremental Update Details")
            report.append("")
            report.append(f"- **Incremental Updates:** {incremental.get('update_count', 0)}")
            report.append(f"- **Trailer Sections:** {incremental.get('trailer_count', 1)}")
            report.append(f"- **XRef Sections:** {incremental.get('xref_sections', 1)}")
            if incremental.get("details"):
                for detail in incremental["details"]:
                    report.append(f"- {detail}")
            if incremental.get("suspicious"):
                report.append("")
                report.append("> ⚠️ **Warning:** Unusual modification pattern detected")
            report.append("")
        
        # Content Changes Section (show actual text additions/deletions)
        revision_content = fp.get("revision_content", {})
        if revision_content.get("has_revisions") and revision_content.get("content_changes"):
            report.append("#### 📝 Content Changes Between Revisions")
            report.append("")
            report.append(f"**{revision_content.get('summary', '')}**")
            report.append("")
            
            # Show additions
            additions = revision_content.get("additions", [])
            if additions:
                report.append("**➕ Text Added:**")
                report.append("")
                for i, addition in enumerate(additions[:10]):  # Limit to 10
                    text = addition.get("text", "")
                    rev = addition.get("revision", "?")
                    report.append(f"{i+1}. (Rev {rev}) `{text}`")
                if len(additions) > 10:
                    report.append(f"   ... and {len(additions) - 10} more additions")
                report.append("")
            
            # Show deletions
            deletions = revision_content.get("deletions", [])
            if deletions:
                report.append("**➖ Text Removed:**")
                report.append("")
                for i, deletion in enumerate(deletions[:10]):  # Limit to 10
                    text = deletion.get("text", "")
                    rev = deletion.get("revision", "?")
                    report.append(f"{i+1}. (Rev {rev}) ~~`{text}`~~")
                if len(deletions) > 10:
                    report.append(f"   ... and {len(deletions) - 10} more deletions")
                report.append("")
            
            # Collapsible detailed diff
            if revision_content.get("content_changes"):
                report.append("<details>")
                report.append("<summary>📄 Detailed Revision Comparison</summary>")
                report.append("")
                
                for change in revision_content["content_changes"]:
                    report.append(f"**Revision {change['from_revision']} → Revision {change['to_revision']}:**")
                    report.append("")
                    report.append("```diff")
                    for line in change.get("diff_lines", [])[:30]:
                        report.append(line)
                    report.append("```")
                    report.append("")
                
                report.append("</details>")
                report.append("")
        elif revision_content.get("has_revisions"):
            report.append("#### 📝 Revision Analysis")
            report.append("")
            report.append(f"*{revision_content.get('summary', 'No content changes detected between revisions')}*")
            report.append("")
        
        # Entropy Analysis (only if suspicious)
        entropy = fp.get("entropy", {})
        if entropy.get("suspicious"):
            report.append("#### 🔒 Entropy Analysis")
            report.append("")
            report.append(f"- **Average Entropy:** {entropy.get('average_entropy', 0)}")
            report.append(f"- **High Entropy Streams:** {entropy.get('high_entropy_count', 0)}")
            report.append("> ⚠️ High entropy may indicate obfuscation or encrypted content")
            report.append("")
        
        # Find matching documents
        same_pipeline_docs = []
        for other_fp in fingerprints:
            if other_fp["file"] != fp["file"] and other_fp["source_hash"] == fp["source_hash"]:
                same_pipeline_docs.append(other_fp["file"])
        
        # Other documents with same pipeline
        report.append("#### Documents with Same Pipeline")
        report.append("")
        if same_pipeline_docs:
            report.append(f"✅ **{len(same_pipeline_docs)} other document(s) share this pipeline:**")
            report.append("")
            for doc in same_pipeline_docs:
                report.append(f"- `{doc}`")
            report.append("")
            report.append("> These documents were generated by the **same backend system**, regardless of content differences.")
        else:
            report.append("ℹ️ **No other documents share this pipeline**")
            report.append("")
            report.append("> This document has a unique generation fingerprint among the analyzed files.")
        report.append("")
        
        # Additional details (collapsible)
        report.append("<details>")
        report.append("<summary>📋 Additional Technical Details</summary>")
        report.append("")
        report.append("**Structure:**")
        report.append(f"- **Object Count:** {fp['structure'].get('object_count', 'N/A')}")
        report.append(f"- **Page Count:** {fp['structure'].get('page_count', 'N/A')}")
        report.append(f"- **Has XFA Forms:** {fp['naming_patterns'].get('has_xfa', False)}")
        report.append(f"- **Has AcroForm:** {fp['naming_patterns'].get('has_acroform', False)}")
        report.append(f"- **Subset Fonts:** {fp['naming_patterns'].get('has_subset_fonts', False)}")
        report.append("")
        
        # Embedded content
        embedded = fp.get("embedded_content", {})
        if embedded.get("image_count", 0) > 0 or embedded.get("embedded_file_count", 0) > 0:
            report.append("**Embedded Content:**")
            report.append(f"- **Images:** {embedded.get('image_count', 0)}")
            if embedded.get("image_formats"):
                formats = ", ".join([f"{img['format']} ({img['count']})" for img in embedded["image_formats"]])
                report.append(f"  - Formats: {formats}")
            if embedded.get("embedded_file_count", 0) > 0:
                report.append(f"- **Embedded Files:** {embedded.get('embedded_file_count', 0)}")
                for ef in embedded.get("embedded_files", []):
                    report.append(f"  - `{ef['name']}` ({ef['size']} bytes)")
            report.append("")
        
        # Entropy details
        entropy = fp.get("entropy", {})
        if entropy.get("total_streams", 0) > 0:
            report.append("**Entropy Analysis:**")
            report.append(f"- **Total Streams Analyzed:** {entropy.get('total_streams', 0)}")
            report.append(f"- **Average Entropy:** {entropy.get('average_entropy', 0)}")
            report.append(f"- **Max Entropy:** {entropy.get('max_entropy', 0)}")
            dist = entropy.get("entropy_distribution", {})
            if dist:
                report.append(f"- **Distribution:** Low: {dist.get('low', 0)}, Medium: {dist.get('medium', 0)}, High: {dist.get('high', 0)}")
            report.append("")
        
        # Timeline
        timeline = fp.get("timeline", {})
        if timeline.get("all_dates"):
            report.append("**Timeline:**")
            for date_entry in timeline["all_dates"]:
                report.append(f"- **{date_entry['source']}:** `{date_entry['value']}`")
            if timeline.get("date_anomalies"):
                report.append("")
                for anomaly in timeline["date_anomalies"]:
                    report.append(f"- ⚠️ {anomaly}")
            report.append("")
        
        if fonts:
            report.append("**All Fonts:**")
            for font in fonts:
                report.append(f"- `{font}`")
        report.append("")
        report.append("</details>")
        report.append("")
        report.append("---")
        report.append("")
    
    # Pipeline Groups
    report.append("## 🔗 Pipeline Groups")
    report.append("")
    report.append("Documents grouped by their generation pipeline:")
    report.append("")
    
    for source_hash, files in similarity["source_groups"].items():
        fp = next(f for f in fingerprints if f["source_hash"] == source_hash)
        source_id = fp.get("source_id", {})
        
        if len(files) > 1:
            report.append(f"### 🟢 Shared Pipeline: `{source_hash}`")
        else:
            report.append(f"### 🔵 Unique Pipeline: `{source_hash}`")
        report.append("")
        report.append(f"**System:** {source_id.get('system', 'Unknown')}")
        report.append("")
        report.append("**Documents:**")
        for f in files:
            report.append(f"- `{f}`")
        report.append("")
    
    # Similarity Matrix (simplified - no Same Source column)
    report.append("## 📈 Similarity Matrix")
    report.append("")
    report.append("Structural similarity between documents (higher = more similar generation process):")
    report.append("")
    report.append("| Document 1 | Document 2 | Similarity |")
    report.append("|------------|------------|:----------:|")
    for sim in similarity["similarities"]:
        score_icon = "🟢" if sim["score"] >= SIMILARITY_SCORE_EXCELLENT_MIN else "🟡" if sim["score"] >= SIMILARITY_SCORE_GOOD_MIN else "🔴"
        report.append(f"| `{sim['file1'][:35]}...` | `{sim['file2'][:35]}...` | {score_icon} **{sim['score']}%** |")
    report.append("")
    
    # Forensic conclusions
    report.append("## 🔬 Forensic Conclusions")
    report.append("")
    
    # Count shared vs unique
    shared_count = sum(1 for files in similarity["source_groups"].values() if len(files) > 1)
    unique_count = sum(1 for files in similarity["source_groups"].values() if len(files) == 1)
    
    report.append(f"### Summary")
    report.append("")
    report.append(f"- **{shared_count}** pipeline(s) are shared between multiple documents")
    report.append(f"- **{unique_count}** pipeline(s) are unique to a single document")
    report.append("")
    
    # Analyze the groups
    for source_hash, files in similarity["source_groups"].items():
        fp = next(f for f in fingerprints if f["source_hash"] == source_hash)
        source_id = fp.get("source_id", {})
        
        if len(files) > 1:
            report.append(f"### 🔗 Shared Pipeline Analysis: {source_id.get('system', 'Unknown')}")
            report.append("")
            report.append(f"**Pipeline Hash:** `{source_hash}`")
            report.append("")
            report.append(f"The following **{len(files)} documents** were created by the **same generation system**:")
            report.append("")
            for f in files:
                report.append(f"1. `{f}`")
            report.append("")
            report.append("**Forensic Evidence:**")
            report.append("")
            report.append("- ✅ Identical pipeline fingerprint")
            report.append("- ✅ Same software/library chain")
            report.append("- ✅ Matching structural patterns")
            report.append("- ✅ Consistent encoding methods")
            report.append("")
            report.append("**Interpretation:**")
            report.append("")
            report.append("These documents originated from the same backend system (e.g., same web portal, same API, same document generation service).")
            report.append("")
    
    # Raw JSON
    report.append("## 📊 Raw Data")
    report.append("")
    report.append("<details>")
    report.append("<summary>Click to expand full JSON data</summary>")
    report.append("")
    report.append("```json")
    report.append(json.dumps({
        "fingerprints": fingerprints,
        "similarity": similarity,
    }, indent=2, default=str))
    report.append("```")
    report.append("")
    report.append("</details>")
    report.append("")
    
    # Write report
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    
    return output_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python pdf_source_identifier.py <pdf_files_or_directory> [--output report.md]")
        print("\nIdentifies the source system of PDF documents and groups by origin.")
        print("Examples:")
        print("  python pdf_source_identifier.py data/")
        print("  python pdf_source_identifier.py file1.pdf file2.pdf file3.pdf")
        print("  python pdf_source_identifier.py data/*.pdf --output report.md")
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


if __name__ == "__main__":
    main()
