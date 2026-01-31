#!/usr/bin/env python3
"""
PDF Forensics Reporting Module
Handles generation of markdown reports for various forensic analysis tools
"""

import json
from datetime import datetime
from typing import List, Dict

__all__ = [
    "generate_source_report",
    "generate_signature_report",
    "generate_markdown_report",
]


def generate_source_report(fingerprints: List[Dict], similarity: Dict, output_path: str):
    """Generate a comprehensive markdown report"""
    report = []
    report.append("# PDF Forensic Analysis Report")
    report.append("")
    report.append(f"**Analysis Date:** {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}")
    report.append(f"**Documents Analyzed:** {len(fingerprints)}")
    report.append("")
    report.append("---")
    report.append("")
    
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
        if integrity_score >= 90:
            integrity_display = f"🟢 {integrity_score}"
        elif integrity_score >= 70:
            integrity_display = f"🟡 {integrity_score}"
        elif integrity_score >= 50:
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
        if integrity_score >= 90:
            integrity_icon = "🟢"
        elif integrity_score >= 70:
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
            if risk_score >= 60:
                risk_icon = "⛔"
            elif risk_score >= 40:
                risk_icon = "🔴"
            elif risk_score >= 20:
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
        score_icon = "🟢" if sim["score"] >= 80 else "🟡" if sim["score"] >= 50 else "🔴"
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


def generate_signature_report(results: dict, output_path: str):
    """Generate a markdown report for signature information"""
    report = []
    report.append("# PDF Digital Signature Report")
    report.append("")
    report.append(f"**File:** `{results['file']}`")
    report.append(f"**Analysis Date:** {results['analysis_time']}")
    report.append("")
    report.append("---")
    report.append("")
    
    # Document Information (Creator/Producer)
    doc_info = results.get("document_info", {})
    if doc_info:
        report.append("## 🔧 Document Creation Information")
        report.append("")
        report.append("| Property | Value |")
        report.append("|----------|-------|")
        report.append(f"| **Creator (Software)** | `{doc_info.get('creator', 'N/A')}` |")
        report.append(f"| **Producer (Library)** | `{doc_info.get('producer', 'N/A')}` |")
        report.append(f"| **Author** | `{doc_info.get('author', 'N/A') or 'Not specified'}` |")
        report.append(f"| **Title** | `{doc_info.get('title', 'N/A') or 'Not specified'}` |")
        report.append(f"| **Subject** | `{doc_info.get('subject', 'N/A') or 'Not specified'}` |")
        report.append(f"| **Keywords** | `{doc_info.get('keywords', 'N/A') or 'Not specified'}` |")
        report.append(f"| **Creation Date** | `{doc_info.get('creation_date', 'N/A')}` |")
        report.append(f"| **Modification Date** | `{doc_info.get('modification_date', 'N/A') or 'Not modified'}` |")
        report.append(f"| **PDF Version** | `{doc_info.get('pdf_version', 'N/A')}` |")
        report.append(f"| **Page Count** | `{doc_info.get('page_count', 'N/A')}` |")
        report.append(f"| **File Size** | `{doc_info.get('file_size_human', 'N/A')}` |")
        report.append("")
        
        # Creator analysis
        creator = doc_info.get('creator', '')
        producer = doc_info.get('producer', '')
        if creator or producer:
            report.append("### 🔍 Creator Analysis")
            report.append("")
            if "pdfsharp" in (creator + producer).lower():
                report.append("- **PDFsharp** is a .NET library for creating PDFs programmatically")
                report.append("- Commonly used in **web applications** for dynamic PDF generation")
                report.append("- Documents are typically generated **on-demand** from templates/databases")
            elif "adobe" in (creator + producer).lower():
                report.append("- Document created with **Adobe** software")
            elif "microsoft" in (creator + producer).lower():
                report.append("- Document created with **Microsoft** software (Word, Print to PDF, etc.)")
            elif "libreoffice" in (creator + producer).lower() or "openoffice" in (creator + producer).lower():
                report.append("- Document created with **LibreOffice/OpenOffice**")
            elif "chrome" in (creator + producer).lower() or "firefox" in (creator + producer).lower():
                report.append("- Document created via **browser print-to-PDF** functionality")
            else:
                report.append(f"- Creator tool: `{creator}`")
                report.append(f"- Producer library: `{producer}`")
            report.append("")
    
    # Fingerprints section
    fingerprints = results.get("fingerprints", {})
    if fingerprints:
        report.append("## 🔐 Document Fingerprints")
        report.append("")
        report.append("Unique identifiers that can be used to track and verify this specific document.")
        report.append("")
        
        # File hashes
        file_hashes = fingerprints.get("file_hashes", {})
        if file_hashes and "error" not in file_hashes:
            report.append("### 📁 File Hashes")
            report.append("")
            report.append("| Algorithm | Hash |")
            report.append("|-----------|------|")
            report.append(f"| **MD5** | `{file_hashes.get('md5', 'N/A')}` |")
            report.append(f"| **SHA1** | `{file_hashes.get('sha1', 'N/A')}` |")
            report.append(f"| **SHA256** | `{file_hashes.get('sha256', 'N/A')}` |")
            report.append("")
        
        # PDF Document IDs
        pdf_ids = fingerprints.get("pdf_ids", {})
        if pdf_ids:
            report.append("### 🆔 PDF Document IDs")
            report.append("")
            report.append("These IDs are generated when the PDF is created and are unique per generation event.")
            report.append("")
            report.append("| Property | Value |")
            report.append("|----------|-------|")
            report.append(f"| **ID[0]** | `{pdf_ids.get('id_0', 'N/A')}` |")
            report.append(f"| **ID[1]** | `{pdf_ids.get('id_1', 'N/A')}` |")
            report.append(f"| **IDs Match** | `{pdf_ids.get('ids_match', 'N/A')}` |")
            report.append("")
            if pdf_ids.get('ids_match'):
                report.append("> ℹ️ Matching IDs indicate this is the **original generation** (not modified after creation)")
            else:
                report.append("> ⚠️ Non-matching IDs indicate the document was **modified after initial creation**")
            report.append("")
        
        # XMP UUIDs
        xmp_uuids = fingerprints.get("xmp_uuids", {})
        if xmp_uuids and (xmp_uuids.get("document_id") or xmp_uuids.get("instance_id")):
            report.append("### 📋 XMP Metadata UUIDs")
            report.append("")
            report.append("| Property | UUID |")
            report.append("|----------|------|")
            report.append(f"| **DocumentID** | `{xmp_uuids.get('document_id', 'N/A')}` |")
            report.append(f"| **InstanceID** | `{xmp_uuids.get('instance_id', 'N/A')}` |")
            report.append("")
        
        # Structure fingerprint
        structure = fingerprints.get("structure", {})
        if structure:
            report.append("### 🏗️ Structure Fingerprint")
            report.append("")
            report.append("| Property | Value |")
            report.append("|----------|-------|")
            report.append(f"| **PDF Version** | `{structure.get('pdf_version', 'N/A')}` |")
            report.append(f"| **Object Count** | `{structure.get('object_count', 'N/A')}` |")
            report.append("")
            
            obj_types = structure.get("object_types", {})
            if obj_types:
                report.append("**Object Types:**")
                report.append("")
                for obj_type, count in sorted(obj_types.items()):
                    report.append(f"- `{obj_type}`: {count}")
                report.append("")
        
        # Font fingerprint
        fonts = fingerprints.get("fonts", [])
        if fonts:
            report.append("### 🔤 Font Fingerprint")
            report.append("")
            report.append("Embedded fonts can identify the source system/template:")
            report.append("")
            for font in fonts:
                report.append(f"- `{font}`")
            report.append("")
        
        # Content hash
        content_hash = fingerprints.get("content_hash")
        if content_hash:
            report.append("### 📝 Content Fingerprint")
            report.append("")
            report.append("Hash of text content only (excludes metadata - useful for comparing document content):")
            report.append("")
            report.append(f"- **SHA256:** `{content_hash}`")
            report.append(f"- **Text Length:** {fingerprints.get('content_length', 'N/A')} characters")
            report.append("")
    
    # Summary
    report.append("## 📋 Signature Summary")
    report.append("")
    
    if results["has_signatures"]:
        report.append(f"✅ **Digital signatures found:** {results['signature_count']}")
    else:
        report.append("❌ **No digital signatures found in this document**")
    
    report.append(f"- **AcroForm present:** {'Yes' if results.get('acroform_present') else 'No'}")
    
    if "sig_flags" in results:
        flags = results["sig_flags"]
        flag_meanings = []
        if flags & 1:
            flag_meanings.append("SignaturesExist")
        if flags & 2:
            flag_meanings.append("AppendOnly")
        report.append(f"- **Signature Flags:** {flags} ({', '.join(flag_meanings) if flag_meanings else 'None'})")
    
    report.append("")
    
    # Signature details
    if results["signatures"]:
        report.append("## 🔏 Signature Objects")
        report.append("")
        
        for i, sig in enumerate(results["signatures"], 1):
            report.append(f"### Signature {i}")
            report.append("")
            report.append("| Property | Value |")
            report.append("|----------|-------|")
            
            for key, value in sig.items():
                if key == "certificate":
                    continue  # Handle separately
                report.append(f"| **{key}** | `{value}` |")
            
            report.append("")
            
            # Certificate info
            if "certificate" in sig:
                cert = sig["certificate"]
                report.append("#### 📜 Certificate Details")
                report.append("")
                report.append("| Property | Value |")
                report.append("|----------|-------|")
                for key, value in cert.items():
                    report.append(f"| **{key}** | `{value}` |")
                report.append("")
    
    # Signature fields
    if results["signature_fields"]:
        report.append("## 📝 Signature Fields")
        report.append("")
        
        for i, field in enumerate(results["signature_fields"], 1):
            report.append(f"### Field {i}")
            report.append("")
            report.append("| Property | Value |")
            report.append("|----------|-------|")
            
            for key, value in field.items():
                if key == "certificate":
                    continue
                report.append(f"| **{key}** | `{value}` |")
            
            report.append("")
            
            if "certificate" in field:
                cert = field["certificate"]
                report.append("#### 📜 Certificate Details")
                report.append("")
                report.append("| Property | Value |")
                report.append("|----------|-------|")
                for key, value in cert.items():
                    report.append(f"| **{key}** | `{value}` |")
                report.append("")
    
    # No signatures explanation
    if not results["has_signatures"]:
        report.append("## ℹ️ What This Means")
        report.append("")
        report.append("This PDF document does not contain any digital signatures. This means:")
        report.append("")
        report.append("- The document has **not been cryptographically signed**")
        report.append("- There is **no way to verify** the document hasn't been modified")
        report.append("- The document's authenticity **cannot be validated** through digital signature verification")
        report.append("")
        report.append("### Common Reasons for Unsigned PDFs:")
        report.append("")
        report.append("1. **Dynamically generated documents** - Many web portals generate PDFs on-the-fly without signing")
        report.append("2. **Draft documents** - Not yet finalized or approved")
        report.append("3. **Internal documents** - Not requiring external verification")
        report.append("4. **Cost considerations** - Digital certificates have associated costs")
        report.append("")
    
    # Raw JSON
    report.append("## 📊 Raw Data")
    report.append("")
    report.append("<details>")
    report.append("<summary>Click to expand full JSON data</summary>")
    report.append("")
    report.append("```json")
    report.append(json.dumps(results, indent=2, default=str))
    report.append("```")
    report.append("")
    report.append("</details>")
    report.append("")
    
    # Write report
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    
    return output_path


def generate_markdown_report(comparison: dict) -> str:
    """Generate a markdown report from comparison results"""
    f1 = comparison["file1"]
    f2 = comparison["file2"]
    
    report = []
    report.append("# PDF Forensic Comparison Report")
    report.append("")
    report.append(f"**Analysis Date:** {comparison['analysis_time']}")
    report.append("")
    report.append("---")
    report.append("")
    
    # Verdict
    report.append("## 🔍 Verdict")
    report.append("")
    report.append(f"**{comparison['verdict']}**")
    report.append("")
    
    # File Overview
    report.append("## 📄 File Overview")
    report.append("")
    report.append("| Property | File 1 | File 2 |")
    report.append("|----------|--------|--------|")
    report.append(f"| **Filename** | `{f1['file']}` | `{f2['file']}` |")
    report.append(f"| **Size** | {f1['file_info'].get('size_human', 'N/A')} | {f2['file_info'].get('size_human', 'N/A')} |")
    report.append(f"| **Pages** | {f1['file_info'].get('page_count', 'N/A')} | {f2['file_info'].get('page_count', 'N/A')} |")
    report.append(f"| **PDF Version** | {f1['file_info'].get('pdf_version', 'N/A')} | {f2['file_info'].get('pdf_version', 'N/A')} |")
    report.append(f"| **Objects** | {f1['file_info'].get('object_count', 'N/A')} | {f2['file_info'].get('object_count', 'N/A')} |")
    report.append(f"| **Encrypted** | {f1['file_info'].get('is_encrypted', 'N/A')} | {f2['file_info'].get('is_encrypted', 'N/A')} |")
    report.append("")
    
    # Metadata Comparison
    report.append("## 📋 Metadata Comparison")
    report.append("")
    report.append("| Field | File 1 | File 2 | Match |")
    report.append("|-------|--------|--------|-------|")
    
    meta_fields = ["title", "author", "subject", "creator", "producer", 
                   "creation_date", "modification_date", "keywords"]
    
    for field in meta_fields:
        val1 = f1.get("metadata", {}).get(field, "") or ""
        val2 = f2.get("metadata", {}).get(field, "") or ""
        match = "✅" if val1 == val2 else "❌"
        # Truncate long values
        val1_display = (val1[:40] + "...") if len(str(val1)) > 40 else val1
        val2_display = (val2[:40] + "...") if len(str(val2)) > 40 else val2
        report.append(f"| **{field}** | {val1_display} | {val2_display} | {match} |")
    
    report.append("")
    
    # Differences
    if comparison["differences"]:
        report.append("## ⚡ Key Differences")
        report.append("")
        for diff in comparison["differences"]:
            report.append(f"### {diff['field']}")
            report.append(f"- **File 1:** `{diff['file1']}`")
            report.append(f"- **File 2:** `{diff['file2']}`")
            report.append("")
    
    # Suspicious Indicators
    all_suspicious_1 = f1.get("suspicious_indicators", [])
    all_suspicious_2 = f2.get("suspicious_indicators", [])
    
    if all_suspicious_1 or all_suspicious_2:
        report.append("## ⚠️ Suspicious Indicators")
        report.append("")
        
        if all_suspicious_1:
            report.append(f"### File 1: `{f1['file']}`")
            for ind in all_suspicious_1:
                report.append(f"- 🚩 {ind}")
            report.append("")
        
        if all_suspicious_2:
            report.append(f"### File 2: `{f2['file']}`")
            for ind in all_suspicious_2:
                report.append(f"- 🚩 {ind}")
            report.append("")
    
    # Raw JSON
    report.append("## 📊 Raw Data")
    report.append("")
    report.append("<details>")
    report.append("<summary>Click to expand full JSON data</summary>")
    report.append("")
    report.append("```json")
    report.append(json.dumps(comparison, indent=2, default=str))
    report.append("```")
    report.append("")
    report.append("</details>")
    report.append("")
    
    return "\n".join(report)
