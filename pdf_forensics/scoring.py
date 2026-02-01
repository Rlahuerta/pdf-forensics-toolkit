#!/usr/bin/env python3
"""
PDF Forensics Toolkit - Scoring Module
Functions for calculating integrity scores, modification scores, and similarity metrics
"""

import pikepdf
from typing import Dict, Any
from pdf_forensics.logging_config import get_logger
from pdf_forensics.constants import (
    SIZE_INCREASE_LARGE_PERCENT,
    SIZE_INCREASE_MEDIUM_PERCENT,
    SIZE_INCREASE_SMALL_PERCENT,
    SCORING_POINTS_SUBSTANTIAL_CHANGE,
    SCORING_POINTS_ID_MISMATCH,
    SCORING_POINTS_DATE_MISMATCH,
    SCORING_POINTS_LARGE_SIZE_INCREASE,
    SCORING_POINTS_MEDIUM_SIZE_INCREASE,
    SCORING_POINTS_SMALL_SIZE_INCREASE,
    SCORING_POINTS_ORPHAN_OBJECTS,
    SCORING_POINTS_HIDDEN_CONTENT,
    SCORING_POINTS_SECURITY_THREAT,
    MAX_ANNOTATIONS_NORMAL,
    MAX_OBJECTS_TO_ANALYZE,
    MAX_SCORE,
    MIN_SCORE,
)

logger = get_logger(__name__)

__all__ = [
    "_calculate_integrity_score",
    "_calculate_similarity",
    "_quantify_changes",
]


def _quantify_changes(pdf_path: str, incremental_data: Dict) -> Dict[str, Any]:
    """Quantify the extent of changes in a PDF document"""
    metrics = {
        "modification_score": 0,  # 0-100 score
        "bytes_added": 0,
        "revision_sizes": [],
        "objects_per_revision": [],
        "content_changes": {},
        "annotation_count": 0,
        "form_field_count": 0,
        "change_types": [],
        "severity": "none",  # none, minor, moderate, significant, major
    }
    
    if not incremental_data.get("was_modified", False):
        metrics["severity"] = "none"
        return metrics
    
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
        
        file_size = len(content)
        
        # Find positions of each %%EOF marker to calculate revision sizes
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
        
        if len(eof_positions) > 1:
            # Calculate size of each revision
            prev_pos = 0
            for i, pos in enumerate(eof_positions):
                revision_size = pos - prev_pos
                metrics["revision_sizes"].append({
                    "revision": i + 1,
                    "size": revision_size,
                    "cumulative": pos,
                })
                prev_pos = pos
            
            # Calculate bytes added in updates (everything after first revision)
            original_size = eof_positions[0]
            metrics["bytes_added"] = file_size - original_size
            metrics["original_size"] = original_size
            metrics["final_size"] = file_size
            metrics["size_increase_percent"] = round((metrics["bytes_added"] / original_size) * 100, 1) if original_size > 0 else 0
    
    except Exception as e:
        metrics["error"] = str(e)
    
    # Analyze object changes using pikepdf
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Count annotations (often added after creation)
            for page in pdf.pages:
                if '/Annots' in page:
                    annots = page['/Annots']
                    if isinstance(annots, pikepdf.Array):
                        metrics["annotation_count"] += len(annots)
            
            # Count form fields
            if '/AcroForm' in pdf.Root:
                acroform = pdf.Root['/AcroForm']
                if '/Fields' in acroform:
                    fields = acroform['/Fields']
                    if isinstance(fields, pikepdf.Array):
                        metrics["form_field_count"] = len(fields)
            
            # Analyze cross-reference structure
            # Objects with generation > 0 were modified
            modified_objects = 0
            total_objects = 0
            for objnum in range(1, min(len(pdf.objects) + 1, MAX_OBJECTS_TO_ANALYZE)):
                try:
                    # Check if object exists
                    obj = pdf.get_object((objnum, 0))
                    if obj is not None:
                        total_objects += 1
                except Exception as e:
                    logger.warning(f"Failed to process annotation: {e}")
            
            metrics["total_objects"] = total_objects
            
    except Exception as e:
        if "error" not in metrics:
            metrics["error"] = str(e)
    
    # Determine change types
    if metrics["bytes_added"] > 0:
        metrics["change_types"].append(f"{metrics['bytes_added']:,} bytes added")
    if metrics["annotation_count"] > 0:
        metrics["change_types"].append(f"{metrics['annotation_count']} annotation(s)")
    if metrics["form_field_count"] > 0:
        metrics["change_types"].append(f"{metrics['form_field_count']} form field(s)")
    if not incremental_data.get("original_id_match", True):
        metrics["change_types"].append("Document ID modified")
    if not incremental_data.get("dates_match", True):
        metrics["change_types"].append("Timestamps differ")
    
    # Calculate modification score (0-100)
    score = 0
    
    # Points for incremental updates
    update_count = incremental_data.get("update_count", 0)
    score += min(update_count * SCORING_POINTS_SUBSTANTIAL_CHANGE, 30)  # Up to 30 points
    
    # Points for ID mismatch
    if not incremental_data.get("original_id_match", True):
        score += SCORING_POINTS_ID_MISMATCH
    
    # Points for date mismatch
    if not incremental_data.get("dates_match", True):
        score += SCORING_POINTS_DATE_MISMATCH
    
    # Points for size increase
    size_increase = metrics.get("size_increase_percent", 0)
    if size_increase > SIZE_INCREASE_LARGE_PERCENT:
        score += SCORING_POINTS_LARGE_SIZE_INCREASE
    elif size_increase > SIZE_INCREASE_MEDIUM_PERCENT:
        score += SCORING_POINTS_MEDIUM_SIZE_INCREASE
    elif size_increase > SIZE_INCREASE_SMALL_PERCENT:
        score += SCORING_POINTS_SMALL_SIZE_INCREASE
    elif size_increase > 0:
        score += 5
    
    # Points for annotations (often indicate manual edits)
    if metrics["annotation_count"] > MAX_ANNOTATIONS_NORMAL:
        score += SCORING_POINTS_SUBSTANTIAL_CHANGE
    elif metrics["annotation_count"] > 0:
        score += SCORING_POINTS_DATE_MISMATCH
    
    metrics["modification_score"] = min(score, MAX_SCORE)
    
    # Determine severity
    if score == 0:
        metrics["severity"] = "none"
    elif score <= 20:
        metrics["severity"] = "minor"
    elif score <= 40:
        metrics["severity"] = "moderate"
    elif score <= 70:
        metrics["severity"] = "significant"
    else:
        metrics["severity"] = "major"
    
    return metrics


def _calculate_integrity_score(fingerprint: Dict) -> int:
    """Calculate an integrity score (0-100) based on forensic indicators"""
    score = MAX_SCORE
    
    # Deduct for incremental updates
    updates = fingerprint.get("incremental_updates", {})
    if updates.get("has_incremental_updates"):
        score -= min(updates.get("update_count", 0) * 5, 20)
    if updates.get("suspicious"):
        score -= 15
    
    # Deduct for security indicators
    security = fingerprint.get("security_indicators", {})
    if security.get("has_javascript"):
        score -= 20
    if security.get("has_launch_action"):
        score -= 25
    if security.get("has_openaction"):
        score -= 5
    
    # Deduct for high entropy (possible obfuscation)
    entropy = fingerprint.get("entropy", {})
    if entropy.get("suspicious"):
        score -= 15
    
    # Deduct for date anomalies
    timeline = fingerprint.get("timeline", {})
    if timeline.get("date_anomalies"):
        score -= 5 * len(timeline["date_anomalies"])
    
    # Deduct for tampering indicators
    tampering = fingerprint.get("tampering", {})
    if tampering.get("is_compromised"):
        confidence = tampering.get("compromise_confidence", "none")
        if confidence == "high":
            score -= 40
        elif confidence == "medium":
            score -= 25
        elif confidence == "low":
            score -= 10
    
    # Additional deductions for specific tampering indicators
    if tampering.get("shadow_attack_risk"):
        score -= 15
    if len(tampering.get("orphan_objects", [])) > 5:
        score -= 10
    if len(tampering.get("metadata_inconsistencies", [])) > 0:
        score -= 10
    
    return max(MIN_SCORE, min(MAX_SCORE, score))


def _calculate_similarity(fp1: Dict, fp2: Dict) -> float:
    """Calculate similarity score between two fingerprints (0-100)"""
    score = 0
    max_score = 0
    
    # Software match (40 points)
    max_score += 40
    if fp1["software"].get("creator_normalized") == fp2["software"].get("creator_normalized"):
        score += 20
    if fp1["software"].get("producer_normalized") == fp2["software"].get("producer_normalized"):
        score += 20
    
    # PDF version match (10 points)
    max_score += 10
    if fp1["structure"].get("pdf_version") == fp2["structure"].get("pdf_version"):
        score += 10
    
    # Filter signature match (15 points)
    max_score += 15
    if fp1["streams"].get("filter_signature") == fp2["streams"].get("filter_signature"):
        score += 15
    
    # Page size match (10 points)
    max_score += 10
    if fp1["page_layout"].get("size_signature") == fp2["page_layout"].get("size_signature"):
        score += 10
    
    # Font overlap (15 points)
    max_score += 15
    fonts1 = set(fp1.get("fonts", []))
    fonts2 = set(fp2.get("fonts", []))
    if fonts1 and fonts2:
        overlap = len(fonts1 & fonts2) / max(len(fonts1 | fonts2), 1)
        score += overlap * 15
    
    # XFA/AcroForm match (10 points)
    max_score += 10
    if fp1["naming_patterns"].get("has_xfa") == fp2["naming_patterns"].get("has_xfa"):
        score += 5
    if fp1["naming_patterns"].get("has_acroform") == fp2["naming_patterns"].get("has_acroform"):
        score += 5
    
    return round((score / max_score) * 100, 1)
