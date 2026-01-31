#!/usr/bin/env python3
"""
PDF Forensics Detection Module - Tampering and security indicator detection
"""

import hashlib
import re
from typing import Dict, Any, List

import fitz  # PyMuPDF
import pikepdf
from pypdf import PdfReader

from pdf_forensics.logging_config import get_logger

logger = get_logger(__name__)

# Common online PDF editors/generators that may indicate manipulation
SUSPICIOUS_PRODUCERS = [
    "ilovepdf", "smallpdf", "pdf24", "sejda", "pdfcandy",
    "online2pdf", "sodapdf", "pdf2go", "cleverpdf",
    "microsoft print to pdf", "chrome", "firefox"
]

__all__ = [
    "_detect_incremental_updates",
    "_detect_tampering_indicators",
    "_detect_security_indicators",
]


def _detect_incremental_updates(pdf_path: str) -> Dict[str, Any]:
    """Detect if PDF has been modified through incremental updates"""
    result = {
        "has_incremental_updates": False,
        "update_count": 0,
        "trailer_count": 1,
        "xref_sections": 1,
        "suspicious": False,
        "details": [],
        # Enhanced modification detection
        "was_modified": False,
        "modification_indicators": [],
        "original_id_match": True,
        "dates_match": True,
        "creation_date": "",
        "modification_date": "",
    }
    
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
            
        # Count %%EOF markers (each indicates a version/update)
        eof_count = content.count(b'%%EOF')
        result["update_count"] = max(0, eof_count - 1)
        result["has_incremental_updates"] = eof_count > 1
        
        # Count startxref entries
        startxref_count = len(re.findall(b'startxref', content))
        result["xref_sections"] = startxref_count
        
        # Count trailer entries
        trailer_count = len(re.findall(b'trailer', content))
        result["trailer_count"] = trailer_count
        
        if eof_count > 1:
            result["details"].append(f"Document has {eof_count - 1} incremental update(s)")
            result["was_modified"] = True
            result["modification_indicators"].append(f"{eof_count - 1} incremental update(s) detected")
            
        if trailer_count > 1:
            result["details"].append(f"Multiple trailer sections detected ({trailer_count})")
            
        # Check for suspicious patterns
        if eof_count > 3:
            result["suspicious"] = True
            result["details"].append("⚠️ Unusually high number of updates - possible tampering")
            
    except Exception as e:
        result["error"] = str(e)
    
    # Check document IDs and dates with pikepdf
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Check PDF Document ID
            # The /ID array contains two hex strings:
            # - First: permanent ID assigned when document was created
            # - Second: ID that changes when document is modified
            if hasattr(pdf, 'trailer') and '/ID' in pdf.trailer:
                doc_id = pdf.trailer['/ID']
                if len(doc_id) >= 2:
                    original_id = bytes(doc_id[0]).hex()
                    current_id = bytes(doc_id[1]).hex()
                    result["original_id"] = original_id
                    result["current_id"] = current_id
                    
                    if original_id != current_id:
                        result["original_id_match"] = False
                        result["was_modified"] = True
                        result["modification_indicators"].append(
                            "Document ID changed after creation (original ≠ current)"
                        )
    except Exception as e:
        logger.warning(f"Failed to check document ID: {e}")
    
    # Check creation vs modification dates
    try:
        doc = fitz.open(pdf_path)
        meta = doc.metadata
        
        creation = meta.get("creationDate", "")
        modification = meta.get("modDate", "")
        
        result["creation_date"] = creation
        result["modification_date"] = modification
        
        if creation and modification:
            # Normalize dates for comparison (remove timezone variations)
            creation_clean = re.sub(r"[+\-]\d{2}'\d{2}'?$", "", creation)
            modification_clean = re.sub(r"[+\-]\d{2}'\d{2}'?$", "", modification)
            
            if creation_clean != modification_clean:
                result["dates_match"] = False
                result["was_modified"] = True
                result["modification_indicators"].append(
                    f"Modification date differs from creation date"
                )
        
        doc.close()
    except Exception as e:
        logger.warning(f"Failed to extract metadata: {e}")
    
    # Import _quantify_changes here to avoid circular import
    from pdf_forensics.scoring import _quantify_changes
    
    # Quantify changes
    result["change_metrics"] = _quantify_changes(pdf_path, result)
    
    # Summary
    if result["was_modified"]:
        result["modification_summary"] = "Document was modified after initial creation"
    else:
        result["modification_summary"] = "No modification detected - appears to be original"
    
    return result


def _compare_library_metadata(pdf_path: str) -> List[str]:
    """Compare metadata extraction across different libraries to find inconsistencies"""
    inconsistencies = []
    
    try:
        # PyMuPDF
        doc = fitz.open(pdf_path)
        fitz_meta = doc.metadata
        doc.close()
        
        # pypdf
        reader = PdfReader(pdf_path)
        pypdf_meta = reader.metadata
        
        if pypdf_meta:
            # Check Creator
            fitz_creator = (fitz_meta.get("creator", "") or "").strip()
            pypdf_creator = (pypdf_meta.creator or "").strip() if pypdf_meta.creator else ""
            
            # Allow for some minor differences (null vs empty string)
            if fitz_creator and pypdf_creator and fitz_creator != pypdf_creator:
                # Sometimes one library decodes differently, check if they are "close"
                if fitz_creator.replace('\x00', '') != pypdf_creator.replace('\x00', ''):
                    inconsistencies.append(f"Metadata mismatch (Creator): PyMuPDF='{fitz_creator}' vs pypdf='{pypdf_creator}'")
            
            # Check Producer
            fitz_producer = (fitz_meta.get("producer", "") or "").strip()
            pypdf_producer = (pypdf_meta.producer or "").strip() if pypdf_meta.producer else ""
            
            if fitz_producer and pypdf_producer and fitz_producer != pypdf_producer:
                if fitz_producer.replace('\x00', '') != pypdf_producer.replace('\x00', ''):
                    inconsistencies.append(f"Metadata mismatch (Producer): PyMuPDF='{fitz_producer}' vs pypdf='{pypdf_producer}'")
                    
    except Exception as e:
        # Don't fail the whole analysis if one library fails
        pass
        
    return inconsistencies


def _detect_tampering_indicators(pdf_path: str) -> Dict[str, Any]:
    """
    Comprehensive tampering and compromise detection.
    Analyzes structural anomalies, orphan objects, hidden content, and more.
    """
    result = {
        "is_compromised": False,
        "compromise_confidence": "none",  # none, low, medium, high
        "risk_score": 0,  # 0-100
        "indicators": [],
        "structural_anomalies": [],
        "hidden_content": [],
        "orphan_objects": [],
        "metadata_inconsistencies": [],
        "page_hashes": [],
        "shadow_attack_risk": False,
        "recommendations": [],
    }
    
    risk_score = 0
    
    # 0. Check for suspicious producers
    try:
        doc = fitz.open(pdf_path)
        meta = doc.metadata
        producer = (meta.get("producer", "") or "").lower()
        creator = (meta.get("creator", "") or "").lower()
        
        for sus in SUSPICIOUS_PRODUCERS:
            if sus in producer or sus in creator:
                result["indicators"].append(f"Document processed with online/suspicious tool: {sus}")
                risk_score += 15
                break
        doc.close()
    except Exception as e:
        logger.warning(f"Failed to extract metadata: {e}")

    # 0.5 Cross-library metadata check
    lib_inconsistencies = _compare_library_metadata(pdf_path)
    if lib_inconsistencies:
        result["metadata_inconsistencies"].extend(lib_inconsistencies)
        result["indicators"].extend(lib_inconsistencies)
        risk_score += len(lib_inconsistencies) * 5
    
    try:
        with open(pdf_path, 'rb') as f:
            raw_content = f.read()
        file_size = len(raw_content)
    except Exception as e:
        result["error"] = str(e)
        return result
    
    # 1. Orphan Object Detection
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Build reference graph
            referenced_objects = set()
            all_objects = set()
            
            # Get all object numbers
            for objnum in range(1, min(len(pdf.objects) + 1, 2000)):
                try:
                    obj = pdf.get_object((objnum, 0))
                    if obj is not None:
                        all_objects.add(objnum)
                except Exception as e:
                    logger.warning(f"Failed during orphan object detection: {e}")
            
            # Trace references from root (Iterative approach to avoid recursion limit)
            stack = []
            visited = set()
            
            # Start from document root and trailer
            try:
                if pdf.Root is not None:
                    stack.append(pdf.Root)
                if hasattr(pdf, 'trailer') and pdf.trailer is not None:
                    stack.append(pdf.trailer)
            except Exception as e:
                logger.warning(f"Failed to check document ID: {e}")
                
            while stack:
                obj = stack.pop()
                
                # Handle indirect objects
                if isinstance(obj, pikepdf.Object):
                    if hasattr(obj, 'objgen') and obj.objgen:
                        objnum = obj.objgen[0]
                        if objnum in visited:
                            continue
                        visited.add(objnum)
                        referenced_objects.add(objnum)
                
                # Traverse children
                try:
                    if isinstance(obj, pikepdf.Dictionary):
                        for key in obj.keys():
                            try:
                                stack.append(obj[key])
                            except Exception as e:
                                logger.warning(f"Operation failed: {e}")
                    elif isinstance(obj, pikepdf.Array):
                        for item in obj:
                            try:
                                stack.append(item)
                            except Exception as e:
                                logger.warning(f"Operation failed: {e}")
                except Exception as e:
                    logger.warning(f"Operation failed: {e}")
            
            # Find orphans
            orphan_count = 0
            for objnum in all_objects:
                if objnum not in referenced_objects:
                    orphan_count += 1
                    if orphan_count <= 5:  # Limit details
                        result["orphan_objects"].append(f"Object {objnum}")
            
            if orphan_count > 0:
                result["indicators"].append(f"{orphan_count} orphan object(s) found - possible remnants of editing")
                if orphan_count > 10:
                    risk_score += 20
                    result["structural_anomalies"].append(f"High orphan count ({orphan_count}) - significant editing history")
                elif orphan_count > 3:
                    risk_score += 10
                else:
                    risk_score += 5
                    
    except Exception as e:
        result["structural_anomalies"].append(f"Error analyzing objects: {str(e)}")
    
    # 2. Hidden Content Detection
    try:
        with pikepdf.open(pdf_path) as pdf:
            hidden_items = []
            
            for page_num, page in enumerate(pdf.pages):
                # Check for hidden annotations
                if '/Annots' in page:
                    annots = page['/Annots']
                    if isinstance(annots, pikepdf.Array):
                        for annot in annots:
                            try:
                                annot_obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                                # Check if annotation is hidden
                                flags = int(annot_obj.get('/F', 0))
                                if flags & 2:  # Hidden flag
                                    hidden_items.append(f"Hidden annotation on page {page_num + 1}")
                                # Check for invisible annotations
                                if annot_obj.get('/Subtype') == '/Text' and flags & 1:  # Invisible
                                    hidden_items.append(f"Invisible text annotation on page {page_num + 1}")
                            except Exception as e:
                                logger.warning(f"Failed to extract object type: {e}")
                
                # Check for optional content (layers)
                if '/Resources' in page:
                    res = page['/Resources']
                    if '/Properties' in res:
                        props = res['/Properties']
                        for key in props.keys():
                            try:
                                prop = props[key]
                                if isinstance(prop, pikepdf.Dictionary):
                                    if prop.get('/Type') == '/OCG':
                                        # Optional Content Group (layer)
                                        name = str(prop.get('/Name', 'Unnamed'))
                                        hidden_items.append(f"Layer '{name}' on page {page_num + 1}")
                            except Exception as e:
                                logger.warning(f"Failed to process annotation: {e}")
            
            # Check for Optional Content in catalog
            if '/OCProperties' in pdf.Root:
                oc_props = pdf.Root['/OCProperties']
                if '/OCGs' in oc_props:
                    ocgs = oc_props['/OCGs']
                    if isinstance(ocgs, pikepdf.Array):
                        layer_count = len(ocgs)
                        if layer_count > 0:
                            result["hidden_content"].append(f"{layer_count} optional content layer(s) detected")
                            risk_score += 10
            
            if hidden_items:
                result["hidden_content"].extend(hidden_items[:10])  # Limit
                risk_score += len(hidden_items) * 5
                result["indicators"].append(f"{len(hidden_items)} hidden element(s) detected")
                
    except Exception as e:
        result["hidden_content"].append(f"Error: {str(e)}")
    
    # 3. Shadow Attack Detection
    try:
        with pikepdf.open(pdf_path) as pdf:
            shadow_risk = False
            
            # Check for multiple content streams per page
            for page_num, page in enumerate(pdf.pages):
                if '/Contents' in page:
                    contents = page['/Contents']
                    if isinstance(contents, pikepdf.Array):
                        # Increased threshold to 10 to reduce false positives
                        if len(contents) > 10:
                            result["structural_anomalies"].append(
                                f"Page {page_num + 1} has {len(contents)} content streams (unusually high)"
                            )
                            # Only flag risk if VERY high or combined with other factors
                            if len(contents) > 50:
                                shadow_risk = True
                
                # Check for suspicious text rendering modes (Tr 3 = invisible text)
                try:
                    # Get content streams for this page
                    page_streams = []
                    if '/Contents' in page:
                        contents = page['/Contents']
                        if isinstance(contents, pikepdf.Array):
                            for ref in contents:
                                page_streams.append(ref)
                        else:
                            page_streams.append(contents)
                    
                    for stream_ref in page_streams:
                        try:
                            stream_obj = stream_ref.get_object() if hasattr(stream_ref, 'get_object') else stream_ref
                            # Read first 4KB to check for Tr mode at start
                            data = stream_obj.read_bytes()
                            # Check for "3 Tr" (invisible text mode)
                            if b'3 Tr' in data or b'3 tr' in data:
                                result["indicators"].append(f"Invisible text rendering (Tr 3) detected on page {page_num + 1}")
                                shadow_risk = True
                        except Exception as e:
                            logger.warning(f"Failed to parse content stream: {e}")
                except Exception as e:
                    logger.warning(f"Failed to parse content stream: {e}")
                
                # Check for form XObjects that could overlay content
                if '/Resources' in page:
                    res = page['/Resources']
                    if '/XObject' in res:
                        xobjects = res['/XObject']
                        form_count = 0
                        for key in xobjects.keys():
                            try:
                                xobj = xobjects[key]
                                if isinstance(xobj, pikepdf.Stream):
                                    if xobj.get('/Subtype') == '/Form':
                                        form_count += 1
                            except Exception as e:
                                logger.warning(f"Failed to extract object type: {e}")
                        if form_count > 10:  # Increased from 5
                            result["structural_anomalies"].append(
                                f"Page {page_num + 1} has {form_count} form XObjects"
                            )
            
            if shadow_risk:
                result["shadow_attack_risk"] = True
                result["indicators"].append("Potential shadow attack structure detected")
                risk_score += 25
                
    except Exception as e:
        pass
    
    # 4. Metadata Consistency Check
    try:
        doc = fitz.open(pdf_path)
        meta = doc.metadata
        
        inconsistencies = []
        
        # Check for suspicious metadata patterns
        creator = meta.get("creator", "") or ""
        producer = meta.get("producer", "") or ""
        
        # Different creator/producer might indicate modification
        if creator and producer:
            creator_base = re.sub(r'[\d\.\s]+', '', creator.lower())
            producer_base = re.sub(r'[\d\.\s]+', '', producer.lower())
            
            # If they're completely different systems
            known_pairs = [
                ("pdfsharp", "pdfsharp"),
                ("adobe", "adobe"),
                ("microsoft", "microsoft"),
                ("designer", "adobe"),
            ]
            
            is_valid_pair = False
            for c, p in known_pairs:
                if c in creator_base and p in producer_base:
                    is_valid_pair = True
                    break
            
            if not is_valid_pair and creator_base and producer_base:
                if creator_base[:5] != producer_base[:5]:
                    inconsistencies.append(
                        f"Creator ({creator[:30]}) and Producer ({producer[:30]}) are from different systems"
                    )
        
        # Check creation vs modification date logic
        creation = meta.get("creationDate", "")
        modification = meta.get("modDate", "")
        
        if creation and modification:
            # Parse dates and check if modification is before creation (impossible)
            try:
                # Extract year from PDF date format
                creation_year = int(re.search(r'D:(\d{4})', creation).group(1)) if creation else 0
                mod_year = int(re.search(r'D:(\d{4})', modification).group(1)) if modification else 0
                
                if mod_year > 0 and creation_year > 0 and mod_year < creation_year:
                    inconsistencies.append(
                        f"Modification date ({modification}) is before creation date ({creation}) - impossible"
                    )
                    risk_score += 30
            except Exception as e:
                logger.warning(f"Failed to extract metadata: {e}")
        
        # Check XMP vs Info dict consistency
        with pikepdf.open(pdf_path) as pdf:
            if pdf.Root.get('/Metadata'):
                try:
                    xmp = bytes(pdf.Root['/Metadata'].read_bytes()).decode('utf-8', errors='ignore')
                    
                    # Extract XMP dates
                    xmp_create = re.search(r'CreateDate["\']?>([^<]+)<', xmp)
                    xmp_modify = re.search(r'ModifyDate["\']?>([^<]+)<', xmp)
                    
                    if xmp_create and creation:
                        # Compare dates (rough check)
                        xmp_date = xmp_create.group(1)[:10]
                        info_date = re.search(r'D:(\d{8})', creation)
                        if info_date:
                            info_formatted = f"{info_date.group(1)[:4]}-{info_date.group(1)[4:6]}-{info_date.group(1)[6:8]}"
                            if xmp_date != info_formatted:
                                inconsistencies.append(
                                    f"XMP CreateDate ({xmp_date}) differs from Info dict ({info_formatted})"
                                )
                                risk_score += 15
                except Exception as e:
                    logger.warning(f"Failed to extract metadata: {e}")
        
        if inconsistencies:
            result["metadata_inconsistencies"] = inconsistencies
            result["indicators"].extend(inconsistencies)
            
        doc.close()
        
    except Exception as e:
        result["metadata_inconsistencies"].append(f"Error: {str(e)}")
    
    # 5. Page Content Hashing (for tamper evidence)
    try:
        doc = fitz.open(pdf_path)
        
        for page_num in range(min(len(doc), 20)):  # Limit to first 20 pages
            page = doc[page_num]
            text = page.get_text()
            
            # Hash the text content
            text_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]
            
            result["page_hashes"].append({
                "page": page_num + 1,
                "content_hash": text_hash,
                "char_count": len(text),
            })
        
        doc.close()
        
    except Exception as e:
        pass
    
    # 6. XREF Structural Analysis
    try:
        # Count XREF sections and check for gaps
        xref_count = len(re.findall(rb'xref\s', raw_content))
        startxref_count = len(re.findall(b'startxref', raw_content))
        
        if xref_count != startxref_count and xref_count > 0:
            result["structural_anomalies"].append(
                f"XREF/startxref mismatch: {xref_count} xref vs {startxref_count} startxref"
            )
            risk_score += 10
        
        # Check for xref streams (PDF 1.5+) vs traditional xref
        xref_stream_count = len(re.findall(rb'/Type\s*/XRef', raw_content))
        if xref_stream_count > 0 and xref_count > 0:
            result["structural_anomalies"].append(
                f"Mixed XREF types: {xref_count} traditional + {xref_stream_count} stream-based"
            )
            risk_score += 5
            
    except Exception as e:
        logger.warning(f"Failed to parse content stream: {e}")
    
    # 7. Calculate Final Risk and Determine Compromise Status
    result["risk_score"] = min(risk_score, 100)
    
    if risk_score >= 60:
        result["is_compromised"] = True
        result["compromise_confidence"] = "high"
        result["recommendations"].append("⛔ Document shows strong signs of tampering - do not trust")
        result["recommendations"].append("Obtain original document from source")
        result["recommendations"].append("Verify with document issuer if possible")
    elif risk_score >= 40:
        result["is_compromised"] = True
        result["compromise_confidence"] = "medium"
        result["recommendations"].append("⚠️ Document shows moderate tampering indicators")
        result["recommendations"].append("Request verification from document source")
        result["recommendations"].append("Compare with known authentic copies")
    elif risk_score >= 20:
        result["is_compromised"] = False
        result["compromise_confidence"] = "low"
        result["recommendations"].append("🔍 Minor anomalies detected - may be normal")
        result["recommendations"].append("Review specific indicators before trusting")
    else:
        result["is_compromised"] = False
        result["compromise_confidence"] = "none"
        result["recommendations"].append("✅ No significant tampering indicators found")
    
    return result


def _detect_security_indicators(pdf_path: str) -> Dict[str, Any]:
    """Detect JavaScript, launch actions, and other security-relevant elements"""
    result = {
        "has_javascript": False,
        "has_launch_action": False,
        "has_embedded_files": False,
        "has_openaction": False,
        "has_aa": False,  # Additional Actions
        "urls_found": [],
        "suspicious_elements": [],
        "risk_level": "low",
    }
    
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Check for OpenAction
            if '/OpenAction' in pdf.Root:
                result["has_openaction"] = True
                result["suspicious_elements"].append("OpenAction detected")
            
            # Check for Additional Actions (AA)
            if '/AA' in pdf.Root:
                result["has_aa"] = True
                result["suspicious_elements"].append("Additional Actions (AA) detected")
            
            # Check for embedded files
            if '/Names' in pdf.Root:
                names = pdf.Root['/Names']
                if '/EmbeddedFiles' in names:
                    result["has_embedded_files"] = True
            
            # Scan all objects for JavaScript and Launch actions
            for objnum in range(1, min(len(pdf.objects) + 1, 1000)):  # Limit scan
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Dictionary):
                        # Check for JavaScript
                        if obj.get('/S') == '/JavaScript' or '/JS' in obj:
                            result["has_javascript"] = True
                            result["suspicious_elements"].append(f"JavaScript in object {objnum}")
                        
                        # Check for Launch action
                        if obj.get('/S') == '/Launch':
                            result["has_launch_action"] = True
                            result["suspicious_elements"].append(f"Launch action in object {objnum}")
                        
                        # Check for URI action and extract URLs
                        if obj.get('/S') == '/URI' and '/URI' in obj:
                            url = str(obj['/URI'])
                            if url not in result["urls_found"]:
                                result["urls_found"].append(url)
                                
                except Exception as e:
                    logger.warning(f"Failed to check for JavaScript/actions: {e}")
            
            # Determine risk level
            if result["has_javascript"] or result["has_launch_action"]:
                result["risk_level"] = "high"
            elif result["has_openaction"] or result["has_aa"]:
                result["risk_level"] = "medium"
            elif result["has_embedded_files"]:
                result["risk_level"] = "low-medium"
                
    except Exception as e:
        result["error"] = str(e)
    
    return result
