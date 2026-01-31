"""
TypedDict definitions for PDF Forensics Toolkit result types.

This module defines the structure of dictionaries returned by forensic analysis functions.
These types enable static type checking and better IDE support.
"""

from __future__ import annotations

from typing import TypedDict, Literal, Any

__all__ = [
    "IncrementalUpdateResult",
    "TamperingResult",
    "SecurityResult",
    "IntegrityScoreResult",
    "SourceFingerprintResult",
    "SignatureExtractionResult",
]


class IncrementalUpdateResult(TypedDict):
    """Result from _detect_incremental_updates() function."""
    has_incremental_updates: bool
    update_count: int
    trailer_count: int
    xref_sections: int
    suspicious: bool
    details: list[str]
    was_modified: bool
    modification_indicators: list[str]
    original_id_match: bool
    dates_match: bool
    creation_date: str
    modification_date: str


class TamperingResult(TypedDict):
    """Result from _detect_tampering_indicators() function."""
    is_compromised: bool
    compromise_confidence: Literal["none", "low", "medium", "high"]
    risk_score: int
    indicators: list[str]
    structural_anomalies: list[str]
    hidden_content: list[str]
    orphan_objects: list[str]
    metadata_inconsistencies: list[str]
    page_hashes: list[Any]
    shadow_attack_risk: bool
    recommendations: list[str]


class SecurityResult(TypedDict):
    """Result from _detect_security_indicators() function."""
    has_javascript: bool
    has_launch_action: bool
    has_embedded_files: bool
    has_openaction: bool
    has_aa: bool
    urls_found: list[str]
    suspicious_elements: list[str]
    risk_level: str


class IntegrityScoreResult(TypedDict):
    """Result from _calculate_integrity_score() function."""
    score: int


class SourceFingerprintResult(TypedDict):
    """Result from extract_source_fingerprint() function."""
    file: str
    file_path: str
    software: dict[str, Any]
    structure: dict[str, Any]
    fonts: list[str]
    streams: dict[str, Any]
    resources: dict[str, Any]
    page_layout: dict[str, Any]
    xmp_namespaces: list[dict[str, str]]
    naming_patterns: dict[str, Any]
    source_hash: str
    incremental_updates: dict[str, Any]
    security_indicators: dict[str, Any]
    entropy: dict[str, Any]
    embedded_content: dict[str, Any]
    timeline: dict[str, Any]
    integrity_score: int


class SignatureExtractionResult(TypedDict):
    """Result from extract_signatures() function."""
    file: str
    file_path: str
    analysis_time: str
    has_signatures: bool
    signature_count: int
    signatures: list[Any]
    signature_fields: list[Any]
    acroform_present: bool
    document_info: dict[str, Any]
    fingerprints: dict[str, str]
