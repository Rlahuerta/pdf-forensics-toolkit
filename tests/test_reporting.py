"""
Unit tests for pdf_forensics.reporting module

Tests all three reporting functions:
- generate_source_report()
- generate_signature_report()
- generate_markdown_report()
"""

import pytest
import json
from pathlib import Path
from datetime import datetime

from pdf_forensics.reporting import (
    generate_source_report,
    generate_signature_report,
    generate_markdown_report,
)


class TestGenerateSourceReport:
    """Test generate_source_report() markdown generation"""
    
    def test_generates_valid_markdown(self, tmp_path):
        """Test that report generates valid markdown output"""
        # Arrange: Create mock fingerprint data
        fingerprints = [
            {
                "file": "document.pdf",
                "file_path": "/path/to/document.pdf",
                "software": {"creator": "Adobe", "producer": "Adobe PDF Library"},
                "structure": {"pdf_version": "1.7", "object_count": 100, "page_count": 5},
                "fonts": ["Arial", "Times New Roman"],
                "streams": {"filter_signature": "FlateDecode"},
                "resources": {},
                "page_layout": {"size_signature": "Letter"},
                "xmp_namespaces": [],
                "naming_patterns": {
                    "has_xfa": False,
                    "has_acroform": False,
                    "has_subset_fonts": True,
                },
                "source_hash": "abc123def456",
                "source_id": {
                    "system": "Adobe Acrobat",
                    "type": "desktop",
                    "confidence": "high",
                },
                "incremental_updates": {
                    "has_incremental_updates": False,
                    "was_modified": False,
                    "modification_summary": "Document appears original",
                    "update_count": 0,
                },
                "tampering": {
                    "is_compromised": False,
                    "risk_score": 0,
                    "indicators": [],
                    "structural_anomalies": [],
                    "hidden_content": [],
                    "orphan_objects": [],
                    "metadata_inconsistencies": [],
                    "shadow_attack_risk": False,
                    "recommendations": [],
                },
                "security_indicators": {
                    "has_javascript": False,
                    "has_launch_action": False,
                    "risk_level": "low",
                },
                "entropy": {"suspicious": False, "average_entropy": 5.2},
                "embedded_content": {"image_count": 0, "embedded_file_count": 0},
                "timeline": {"all_dates": [], "date_anomalies": []},
                "integrity_score": 100,
            }
        ]
        
        similarity = {
            "group_count": 1,
            "source_groups": {
                "abc123def456": ["document.pdf"]
            },
            "similarities": [],
        }
        
        output_file = tmp_path / "report.md"
        
        # Act: Call generate_source_report()
        result = generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert: File exists and contains expected sections
        assert output_file.exists()
        content = output_file.read_text()
        
        # Verify key sections
        assert "# PDF Forensic Analysis Report" in content
        assert "## 📊 Executive Summary" in content
        assert "## 📄 Individual Document Analysis" in content
        assert "## 🔗 Pipeline Groups" in content
        assert "document.pdf" in content
        assert "Integrity Score" in content
    
    def test_handles_multiple_documents(self, tmp_path):
        """Test report with multiple documents"""
        # Create 2 documents with different sources
        fingerprints = []
        for i in range(2):
            fingerprints.append({
                "file": f"doc{i}.pdf",
                "file_path": f"/path/to/doc{i}.pdf",
                "software": {"creator": "Test", "producer": "Test"},
                "structure": {"pdf_version": "1.7", "object_count": 50, "page_count": 1},
                "fonts": [],
                "streams": {"filter_signature": "FlateDecode"},
                "resources": {},
                "page_layout": {"size_signature": "Letter"},
                "xmp_namespaces": [],
                "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
                "source_hash": f"hash{i}",
                "source_id": {"system": "Test System", "type": "test", "confidence": "medium"},
                "incremental_updates": {"has_incremental_updates": False, "was_modified": False, "update_count": 0},
                "tampering": {
                    "is_compromised": False,
                    "risk_score": 0,
                    "indicators": [],
                    "structural_anomalies": [],
                    "hidden_content": [],
                    "orphan_objects": [],
                    "metadata_inconsistencies": [],
                    "shadow_attack_risk": False,
                    "recommendations": [],
                },
                "security_indicators": {"has_javascript": False, "has_launch_action": False, "risk_level": "low"},
                "entropy": {"suspicious": False},
                "embedded_content": {},
                "timeline": {},
                "integrity_score": 95,
            })
        
        similarity = {
            "group_count": 2,
            "source_groups": {
                "hash0": ["doc0.pdf"],
                "hash1": ["doc1.pdf"],
            },
            "similarities": [
                {"file1": "doc0.pdf", "file2": "doc1.pdf", "score": 45}
            ],
        }
        
        output_file = tmp_path / "multi_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "**Documents Analyzed:** 2" in content
        assert "doc0.pdf" in content
        assert "doc1.pdf" in content
        assert "## 📈 Similarity Matrix" in content
    
    def test_handles_tampering_indicators(self, tmp_path):
        """Test report shows tampering indicators properly"""
        fingerprints = [{
            "file": "suspicious.pdf",
            "file_path": "/path/to/suspicious.pdf",
            "software": {"creator": "Unknown", "producer": "Unknown"},
            "structure": {"pdf_version": "1.4", "object_count": 200, "page_count": 1},
            "fonts": [],
            "streams": {"filter_signature": "None"},
            "resources": {},
            "page_layout": {"size_signature": "Letter"},
            "xmp_namespaces": [],
            "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
            "source_hash": "suspicious123",
            "source_id": {"system": "Unknown", "type": "unknown", "confidence": "low"},
            "incremental_updates": {
                "has_incremental_updates": True,
                "was_modified": True,
                "update_count": 3,
                "change_metrics": {
                    "modification_score": 75,
                    "severity": "significant",
                    "bytes_added": 5000,
                    "size_increase_percent": 25,
                },
                "modification_indicators": ["Multiple incremental updates detected"],
            },
            "tampering": {
                "is_compromised": True,
                "compromise_confidence": "high",
                "risk_score": 80,
                "indicators": ["Orphan objects detected", "ID mismatch"],
                "structural_anomalies": ["Unusual xref structure"],
                "hidden_content": ["Hidden layer found"],
                "orphan_objects": ["Object 123", "Object 456"],
                "metadata_inconsistencies": ["Creation date after modification date"],
                "shadow_attack_risk": True,
                "recommendations": ["Do not trust this document", "Request original from source"],
            },
            "security_indicators": {"has_javascript": False, "has_launch_action": False, "risk_level": "medium"},
            "entropy": {"suspicious": True, "average_entropy": 7.8, "high_entropy_count": 5},
            "embedded_content": {},
            "timeline": {},
            "integrity_score": 25,
        }]
        
        similarity = {
            "group_count": 1,
            "source_groups": {"suspicious123": ["suspicious.pdf"]},
            "similarities": [],
        }
        
        output_file = tmp_path / "tampering_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "⛔" in content or "⚠️" in content  # Alert icons
        assert "SECURITY ALERT" in content
        assert "Potentially Compromised" in content
        assert "Orphan objects detected" in content
        assert "Do not trust this document" in content
        assert "🔴" in content  # Red integrity score icon
    
    def test_handles_security_threats(self, tmp_path):
        """Test report shows security threats properly"""
        fingerprints = [{
            "file": "threat.pdf",
            "file_path": "/path/to/threat.pdf",
            "software": {"creator": "Test", "producer": "Test"},
            "structure": {"pdf_version": "1.7", "object_count": 50, "page_count": 1},
            "fonts": [],
            "streams": {"filter_signature": "FlateDecode"},
            "resources": {},
            "page_layout": {"size_signature": "Letter"},
            "xmp_namespaces": [],
            "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
            "source_hash": "threat123",
            "source_id": {"system": "Test", "type": "test", "confidence": "medium"},
            "incremental_updates": {"has_incremental_updates": False, "was_modified": False, "update_count": 0},
            "tampering": {
                "is_compromised": False,
                "risk_score": 0,
                "indicators": [],
                "structural_anomalies": [],
                "hidden_content": [],
                "orphan_objects": [],
                "metadata_inconsistencies": [],
                "shadow_attack_risk": False,
                "recommendations": [],
            },
            "security_indicators": {
                "has_javascript": True,
                "has_launch_action": True,
                "has_embedded_files": True,
                "risk_level": "high",
                "suspicious_elements": ["JavaScript code detected", "Launch action found"],
                "urls_found": ["http://example.com/malicious"],
            },
            "entropy": {"suspicious": False},
            "embedded_content": {},
            "timeline": {},
            "integrity_score": 60,
        }]
        
        similarity = {
            "group_count": 1,
            "source_groups": {"threat123": ["threat.pdf"]},
            "similarities": [],
        }
        
        output_file = tmp_path / "threat_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "⚠️ Security Indicators" in content
        assert "JavaScript code detected" in content
        assert "http://example.com/malicious" in content
        assert "HIGH" in content or "high" in content
    
    def test_handles_same_pipeline_documents(self, tmp_path):
        """Test grouping documents with same pipeline"""
        # Create 2 documents with same source hash
        fingerprints = []
        for i in range(2):
            fingerprints.append({
                "file": f"same_source_{i}.pdf",
                "file_path": f"/path/to/same_source_{i}.pdf",
                "software": {"creator": "PDFsharp", "producer": "PDFsharp"},
                "structure": {"pdf_version": "1.4", "object_count": 50, "page_count": 1},
                "fonts": ["Arial"],
                "streams": {"filter_signature": "FlateDecode"},
                "resources": {},
                "page_layout": {"size_signature": "A4"},
                "xmp_namespaces": [],
                "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
                "source_hash": "same_hash_123",  # SAME hash
                "source_id": {"system": "PDFsharp (.NET)", "type": "library", "confidence": "high"},
                "incremental_updates": {"has_incremental_updates": False, "was_modified": False, "update_count": 0},
                "tampering": {
                    "is_compromised": False,
                    "risk_score": 0,
                    "indicators": [],
                    "structural_anomalies": [],
                    "hidden_content": [],
                    "orphan_objects": [],
                    "metadata_inconsistencies": [],
                    "shadow_attack_risk": False,
                    "recommendations": [],
                },
                "security_indicators": {"has_javascript": False, "has_launch_action": False, "risk_level": "low"},
                "entropy": {"suspicious": False},
                "embedded_content": {},
                "timeline": {},
                "integrity_score": 100,
            })
        
        similarity = {
            "group_count": 1,
            "source_groups": {
                "same_hash_123": ["same_source_0.pdf", "same_source_1.pdf"]
            },
            "similarities": [
                {"file1": "same_source_0.pdf", "file2": "same_source_1.pdf", "score": 100}
            ],
        }
        
        output_file = tmp_path / "same_pipeline_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "## 🔗 Pipeline Groups" in content
        assert "same backend system" in content or "Shared Pipeline" in content
        assert "same_source_0.pdf" in content
        assert "same_source_1.pdf" in content
    
    def test_contains_all_required_sections(self, tmp_path):
        """Test that report contains all major sections"""
        fingerprints = [{
            "file": "complete.pdf",
            "file_path": "/path/to/complete.pdf",
            "software": {"creator": "Test", "producer": "Test"},
            "structure": {"pdf_version": "1.7", "object_count": 50, "page_count": 1},
            "fonts": [],
            "streams": {"filter_signature": "FlateDecode"},
            "resources": {},
            "page_layout": {"size_signature": "Letter"},
            "xmp_namespaces": [],
            "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
            "source_hash": "complete123",
            "source_id": {"system": "Test", "type": "test", "confidence": "high"},
            "incremental_updates": {"has_incremental_updates": False, "was_modified": False, "update_count": 0},
            "tampering": {
                "is_compromised": False,
                "risk_score": 0,
                "indicators": [],
                "structural_anomalies": [],
                "hidden_content": [],
                "orphan_objects": [],
                "metadata_inconsistencies": [],
                "shadow_attack_risk": False,
                "recommendations": [],
            },
            "security_indicators": {"has_javascript": False, "has_launch_action": False, "risk_level": "low"},
            "entropy": {"suspicious": False},
            "embedded_content": {},
            "timeline": {},
            "integrity_score": 95,
        }]
        
        similarity = {
            "group_count": 1,
            "source_groups": {"complete123": ["complete.pdf"]},
            "similarities": [],
        }
        
        output_file = tmp_path / "complete_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        
        # Check all major sections
        required_sections = [
            "# PDF Forensic Analysis Report",
            "## 📖 How to Read This Report",
            "## 📊 Executive Summary",
            "## 📄 Individual Document Analysis",
            "## 🔗 Pipeline Groups",
            "## 📈 Similarity Matrix",
            "## 🔬 Forensic Conclusions",
            "## 📊 Raw Data",
        ]
        
        for section in required_sections:
            assert section in content, f"Missing section: {section}"
    
    def test_handles_content_changes(self, tmp_path):
        """Test report shows content changes between revisions"""
        fingerprints = [{
            "file": "revised.pdf",
            "file_path": "/path/to/revised.pdf",
            "software": {"creator": "Test", "producer": "Test"},
            "structure": {"pdf_version": "1.7", "object_count": 50, "page_count": 1},
            "fonts": [],
            "streams": {"filter_signature": "FlateDecode"},
            "resources": {},
            "page_layout": {"size_signature": "Letter"},
            "xmp_namespaces": [],
            "naming_patterns": {"has_xfa": False, "has_acroform": False, "has_subset_fonts": False},
            "source_hash": "revised123",
            "source_id": {"system": "Test", "type": "test", "confidence": "high"},
            "incremental_updates": {"has_incremental_updates": True, "was_modified": True, "update_count": 2},
            "tampering": {
                "is_compromised": False,
                "risk_score": 15,
                "indicators": [],
                "structural_anomalies": [],
                "hidden_content": [],
                "orphan_objects": [],
                "metadata_inconsistencies": [],
                "shadow_attack_risk": False,
                "recommendations": [],
            },
            "security_indicators": {"has_javascript": False, "has_launch_action": False, "risk_level": "low"},
            "entropy": {"suspicious": False},
            "embedded_content": {},
            "timeline": {},
            "integrity_score": 85,
            "revision_content": {
                "has_revisions": True,
                "content_changes": [
                    {
                        "from_revision": 1,
                        "to_revision": 2,
                        "diff_lines": ["+ Added text", "- Removed text"],
                    }
                ],
                "summary": "Text changes detected",
                "additions": [{"text": "New content", "revision": 2}],
                "deletions": [{"text": "Old content", "revision": 1}],
            },
        }]
        
        similarity = {
            "group_count": 1,
            "source_groups": {"revised123": ["revised.pdf"]},
            "similarities": [],
        }
        
        output_file = tmp_path / "revision_report.md"
        
        # Act
        generate_source_report(fingerprints, similarity, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "📝 Content Changes Between Revisions" in content
        assert "➕ Text Added" in content
        assert "➖ Text Removed" in content
        assert "New content" in content
        assert "Old content" in content


class TestGenerateSignatureReport:
    """Test generate_signature_report() markdown generation"""
    
    def test_generates_valid_markdown(self, tmp_path):
        """Test that report generates valid markdown output"""
        # Arrange: Create mock signature data
        signature_data = {
            "file": "signed.pdf",
            "file_path": "/path/to/signed.pdf",
            "analysis_time": datetime.now().isoformat(),
            "has_signatures": True,
            "signature_count": 1,
            "signatures": [
                {
                    "type": "/Sig",
                    "filter": "/Adobe.PPKLite",
                    "subfilter": "/adbe.pkcs7.detached",
                    "certificate": {
                        "subject": "CN=John Doe",
                        "issuer": "CN=Test CA",
                        "serial_number": "123456",
                        "not_before": "2024-01-01",
                        "not_after": "2025-01-01",
                    }
                }
            ],
            "signature_fields": [],
            "acroform_present": True,
            "sig_flags": 3,
            "document_info": {
                "creator": "Adobe Acrobat",
                "producer": "Adobe PDF Library",
                "author": "Test Author",
                "title": "Test Document",
                "subject": "",
                "keywords": "",
                "creation_date": "2024-01-01T00:00:00",
                "modification_date": "2024-01-02T00:00:00",
                "pdf_version": "1.7",
                "page_count": 5,
                "file_size_human": "1.5 MB",
            },
            "fingerprints": {
                "file_hashes": {
                    "md5": "abc123def456",
                    "sha1": "def456abc789",
                    "sha256": "789abc123def456",
                },
                "pdf_ids": {
                    "id_0": "id0_value",
                    "id_1": "id1_value",
                    "ids_match": True,
                },
                "content_hash": "content_hash_123",
                "content_length": 5000,
            },
        }
        
        output_file = tmp_path / "sig_report.md"
        
        # Act
        result = generate_signature_report(signature_data, str(output_file))
        
        # Assert
        assert output_file.exists()
        content = output_file.read_text()
        
        # Verify key sections
        assert "# PDF Digital Signature Report" in content
        assert "signed.pdf" in content
        assert "## 🔐 Document Fingerprints" in content
        assert "## 📋 Signature Summary" in content
        assert "✅ **Digital signatures found:** 1" in content
    
    def test_handles_unsigned_document(self, tmp_path):
        """Test report for document without signatures"""
        signature_data = {
            "file": "unsigned.pdf",
            "file_path": "/path/to/unsigned.pdf",
            "analysis_time": datetime.now().isoformat(),
            "has_signatures": False,
            "signature_count": 0,
            "signatures": [],
            "signature_fields": [],
            "acroform_present": False,
            "document_info": {
                "creator": "Test",
                "producer": "Test",
                "pdf_version": "1.4",
                "page_count": 1,
                "file_size_human": "100 KB",
            },
            "fingerprints": {},
        }
        
        output_file = tmp_path / "unsigned_report.md"
        
        # Act
        generate_signature_report(signature_data, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "❌ **No digital signatures found" in content
        assert "## ℹ️ What This Means" in content
        assert "not been cryptographically signed" in content
    
    def test_includes_certificate_details(self, tmp_path):
        """Test that certificate information is included"""
        signature_data = {
            "file": "cert_test.pdf",
            "file_path": "/path/to/cert_test.pdf",
            "analysis_time": datetime.now().isoformat(),
            "has_signatures": True,
            "signature_count": 1,
            "signatures": [
                {
                    "certificate": {
                        "subject": "CN=Jane Smith, O=Acme Corp",
                        "issuer": "CN=GlobalSign CA",
                        "serial_number": "987654321",
                        "not_before": "2023-01-01T00:00:00",
                        "not_after": "2026-01-01T00:00:00",
                    }
                }
            ],
            "signature_fields": [],
            "acroform_present": True,
            "document_info": {},
            "fingerprints": {},
        }
        
        output_file = tmp_path / "cert_report.md"
        
        # Act
        generate_signature_report(signature_data, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "📜 Certificate Details" in content
        assert "Jane Smith" in content
        assert "GlobalSign CA" in content
        assert "987654321" in content
    
    def test_includes_file_hashes(self, tmp_path):
        """Test that file hashes are included in report"""
        signature_data = {
            "file": "hash_test.pdf",
            "file_path": "/path/to/hash_test.pdf",
            "analysis_time": datetime.now().isoformat(),
            "has_signatures": False,
            "signature_count": 0,
            "signatures": [],
            "signature_fields": [],
            "acroform_present": False,
            "document_info": {},
            "fingerprints": {
                "file_hashes": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
            },
        }
        
        output_file = tmp_path / "hash_report.md"
        
        # Act
        generate_signature_report(signature_data, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "### 📁 File Hashes" in content
        assert "d41d8cd98f00b204e9800998ecf8427e" in content
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in content
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in content
    
    def test_includes_creator_analysis(self, tmp_path):
        """Test creator analysis section"""
        signature_data = {
            "file": "creator_test.pdf",
            "file_path": "/path/to/creator_test.pdf",
            "analysis_time": datetime.now().isoformat(),
            "has_signatures": False,
            "signature_count": 0,
            "signatures": [],
            "signature_fields": [],
            "acroform_present": False,
            "document_info": {
                "creator": "PDFsharp 1.50.0",
                "producer": "PDFsharp 1.50.0 (.NET)",
                "pdf_version": "1.4",
                "page_count": 1,
                "file_size_human": "50 KB",
            },
            "fingerprints": {},
        }
        
        output_file = tmp_path / "creator_report.md"
        
        # Act
        generate_signature_report(signature_data, str(output_file))
        
        # Assert
        content = output_file.read_text()
        assert "### 🔍 Creator Analysis" in content
        assert "PDFsharp" in content
        assert ".NET library" in content or "web applications" in content


class TestGenerateMarkdownReport:
    """Test generate_markdown_report() markdown generation for comparison"""
    
    def test_generates_valid_markdown(self, tmp_path):
        """Test that comparison report generates valid markdown"""
        # Arrange: Create comparison data
        comparison = {
            "file1": {
                "file": "doc1.pdf",
                "file_info": {
                    "size_human": "1 MB",
                    "page_count": 5,
                    "pdf_version": "1.7",
                    "object_count": 100,
                    "is_encrypted": False,
                },
                "metadata": {
                    "title": "Document 1",
                    "author": "Author 1",
                    "subject": "",
                    "creator": "Adobe",
                    "producer": "Adobe PDF Library",
                    "creation_date": "2024-01-01",
                    "modification_date": "2024-01-02",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "file2": {
                "file": "doc2.pdf",
                "file_info": {
                    "size_human": "1.1 MB",
                    "page_count": 5,
                    "pdf_version": "1.7",
                    "object_count": 105,
                    "is_encrypted": False,
                },
                "metadata": {
                    "title": "Document 1",
                    "author": "Author 2",
                    "subject": "",
                    "creator": "Adobe",
                    "producer": "Adobe PDF Library",
                    "creation_date": "2024-01-01",
                    "modification_date": "2024-01-03",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "analysis_time": datetime.now().isoformat(),
            "verdict": "Files are different",
            "differences": [
                {"field": "author", "file1": "Author 1", "file2": "Author 2"},
                {"field": "modification_date", "file1": "2024-01-02", "file2": "2024-01-03"},
            ],
        }
        
        # Act
        result = generate_markdown_report(comparison)
        
        # Assert
        assert "# PDF Forensic Comparison Report" in result
        assert "## 🔍 Verdict" in result
        assert "Files are different" in result
        assert "## 📄 File Overview" in result
        assert "## 📋 Metadata Comparison" in result
    
    def test_shows_differences_correctly(self, tmp_path):
        """Test that differences are displayed in report"""
        comparison = {
            "file1": {
                "file": "original.pdf",
                "file_info": {"size_human": "1 MB", "page_count": 3, "pdf_version": "1.4", "object_count": 50, "is_encrypted": False},
                "metadata": {
                    "title": "Original Title",
                    "author": "Original Author",
                    "subject": "",
                    "creator": "Creator A",
                    "producer": "Producer A",
                    "creation_date": "2024-01-01",
                    "modification_date": "",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "file2": {
                "file": "modified.pdf",
                "file_info": {"size_human": "1.2 MB", "page_count": 3, "pdf_version": "1.4", "object_count": 55, "is_encrypted": False},
                "metadata": {
                    "title": "Modified Title",
                    "author": "Modified Author",
                    "subject": "",
                    "creator": "Creator A",
                    "producer": "Producer A",
                    "creation_date": "2024-01-01",
                    "modification_date": "2024-01-10",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "analysis_time": datetime.now().isoformat(),
            "verdict": "Files have differences",
            "differences": [
                {"field": "title", "file1": "Original Title", "file2": "Modified Title"},
                {"field": "author", "file1": "Original Author", "file2": "Modified Author"},
                {"field": "modification_date", "file1": "", "file2": "2024-01-10"},
            ],
        }
        
        # Act
        result = generate_markdown_report(comparison)
        
        # Assert
        assert "## ⚡ Key Differences" in result
        assert "title" in result
        assert "author" in result
        assert "Original Title" in result
        assert "Modified Title" in result
        assert "❌" in result  # Mismatch indicator
    
    def test_handles_suspicious_indicators(self, tmp_path):
        """Test that suspicious indicators are shown"""
        comparison = {
            "file1": {
                "file": "clean.pdf",
                "file_info": {"size_human": "1 MB", "page_count": 1, "pdf_version": "1.7", "object_count": 50, "is_encrypted": False},
                "metadata": {
                    "title": "", "author": "", "subject": "", "creator": "Test", "producer": "Test",
                    "creation_date": "", "modification_date": "", "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "file2": {
                "file": "suspicious.pdf",
                "file_info": {"size_human": "1 MB", "page_count": 1, "pdf_version": "1.7", "object_count": 60, "is_encrypted": False},
                "metadata": {
                    "title": "", "author": "", "subject": "", "creator": "Test", "producer": "Test",
                    "creation_date": "", "modification_date": "", "keywords": "",
                },
                "suspicious_indicators": [
                    "Contains JavaScript",
                    "Has launch action",
                    "Orphan objects detected",
                ],
            },
            "analysis_time": datetime.now().isoformat(),
            "verdict": "Files are different with security concerns",
            "differences": [],
        }
        
        # Act
        result = generate_markdown_report(comparison)
        
        # Assert
        assert "## ⚠️ Suspicious Indicators" in result
        assert "Contains JavaScript" in result
        assert "Has launch action" in result
        assert "Orphan objects detected" in result
        assert "🚩" in result
    
    def test_metadata_comparison_table(self, tmp_path):
        """Test metadata comparison table generation"""
        comparison = {
            "file1": {
                "file": "file1.pdf",
                "file_info": {"size_human": "500 KB", "page_count": 2, "pdf_version": "1.4", "object_count": 30, "is_encrypted": False},
                "metadata": {
                    "title": "Same Title",
                    "author": "Different Author 1",
                    "subject": "Same Subject",
                    "creator": "Same Creator",
                    "producer": "Different Producer 1",
                    "creation_date": "2024-01-01",
                    "modification_date": "2024-01-01",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "file2": {
                "file": "file2.pdf",
                "file_info": {"size_human": "500 KB", "page_count": 2, "pdf_version": "1.4", "object_count": 30, "is_encrypted": False},
                "metadata": {
                    "title": "Same Title",
                    "author": "Different Author 2",
                    "subject": "Same Subject",
                    "creator": "Same Creator",
                    "producer": "Different Producer 2",
                    "creation_date": "2024-01-01",
                    "modification_date": "2024-01-01",
                    "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "analysis_time": datetime.now().isoformat(),
            "verdict": "Files have some differences",
            "differences": [],
        }
        
        # Act
        result = generate_markdown_report(comparison)
        
        # Assert
        assert "| Field | File 1 | File 2 | Match |" in result
        assert "Same Title" in result
        assert "Same Creator" in result
        assert "Different Author 1" in result
        assert "Different Author 2" in result
        # Check for both checkmarks and crosses
        assert "✅" in result  # Matching fields
        assert "❌" in result  # Non-matching fields
    
    def test_contains_raw_json_data(self, tmp_path):
        """Test that raw JSON data is included"""
        comparison = {
            "file1": {
                "file": "test1.pdf",
                "file_info": {"size_human": "1 MB", "page_count": 1, "pdf_version": "1.7", "object_count": 50, "is_encrypted": False},
                "metadata": {
                    "title": "", "author": "", "subject": "", "creator": "Test", "producer": "Test",
                    "creation_date": "", "modification_date": "", "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "file2": {
                "file": "test2.pdf",
                "file_info": {"size_human": "1 MB", "page_count": 1, "pdf_version": "1.7", "object_count": 50, "is_encrypted": False},
                "metadata": {
                    "title": "", "author": "", "subject": "", "creator": "Test", "producer": "Test",
                    "creation_date": "", "modification_date": "", "keywords": "",
                },
                "suspicious_indicators": [],
            },
            "analysis_time": datetime.now().isoformat(),
            "verdict": "Files are identical",
            "differences": [],
        }
        
        # Act
        result = generate_markdown_report(comparison)
        
        # Assert
        assert "## 📊 Raw Data" in result
        assert "<details>" in result
        assert "```json" in result
        assert "test1.pdf" in result
        assert "test2.pdf" in result
