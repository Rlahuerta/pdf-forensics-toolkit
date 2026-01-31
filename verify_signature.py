#!/usr/bin/env python3
"""
PDF Digital Signature Verification Tool
Extracts and verifies digital signatures from PDF documents
Includes fingerprint/hash tracking for document provenance
"""

import sys
import json
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

import fitz  # PyMuPDF
import pikepdf
from cryptography import x509

from pdf_forensics.logging_config import get_logger
from pdf_forensics.reporting import generate_signature_report
from pdf_forensics.signature import validate_signature as validate_signature_pyhanko
from pdf_forensics.types import SignatureExtractionResult

logger = get_logger(__name__)


def extract_signatures(pdf_path: str) -> SignatureExtractionResult:
    """Extract digital signature information from a PDF file"""
    results = {
        "file": Path(pdf_path).name,
        "file_path": pdf_path,
        "analysis_time": datetime.now().isoformat(),
        "has_signatures": False,
        "signature_count": 0,
        "signatures": [],
        "signature_fields": [],
        "acroform_present": False,
        "document_info": {},
        "fingerprints": {},
    }
    
    path = Path(pdf_path)
    if not path.exists():
        results["error"] = str("File not found")
        return results  # type: ignore[return-value] -- results dict has dynamic "error" key, TypedDict allows extra keys at runtime

    # Extract fingerprints/hashes
    results["fingerprints"] = _extract_fingerprints(pdf_path)

    # Extract document creator/producer information
    try:
        with fitz.open(pdf_path) as doc:
            meta = doc.metadata
            file_stat = path.stat()
            if meta:  # type: ignore[truthy-function] -- fitz metadata can be None, stubs don't reflect this
                results["document_info"] = {
                    "title": meta.get("title", "") or "",
                    "author": meta.get("author", "") or "",
                    "subject": meta.get("subject", "") or "",
                    "keywords": meta.get("keywords", "") or "",
                    "creator": meta.get("creator", "") or "",
                    "producer": meta.get("producer", "") or "",
                    "creation_date": meta.get("creationDate", "") or "",
                    "modification_date": meta.get("modDate", "") or "",
                    "pdf_version": meta.get("format", "") or "",
                    "page_count": doc.page_count,
                    "file_size_bytes": file_stat.st_size,
                    "file_size_human": _human_size(file_stat.st_size),
                }
            else:
                results["document_info"] = {
                    "page_count": doc.page_count,
                    "file_size_bytes": file_stat.st_size,
                    "file_size_human": _human_size(file_stat.st_size),
                }
    except Exception as e:
        results["document_info"]["error"] = str(e)

    # Check with pikepdf for signature fields
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Check for AcroForm (interactive form fields including signatures)
            if "/AcroForm" in pdf.Root:
                results["acroform_present"] = True
                acroform = pdf.Root["/AcroForm"]
                
                # Check for signature fields
                if "/Fields" in acroform:
                    fields = acroform["/Fields"]
                    for field in fields:
                        try:
                            field_obj = field.get_object() if hasattr(field, 'get_object') else field
                            field_type = str(field_obj.get("/FT", ""))
                            
                            if field_type == "/Sig":
                                sig_info = _extract_signature_field(field_obj)
                                results["signature_fields"].append(sig_info)
                        except Exception as e:
                            results["signature_fields"].append({"error": str(e)})
                
                # Check SigFlags
                if "/SigFlags" in acroform:
                    results["sig_flags"] = int(acroform["/SigFlags"])
            
            # Look for signature objects directly
            for objnum in range(1, len(pdf.objects) + 1):
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Dictionary):
                        if obj.get("/Type") == "/Sig" or "/ByteRange" in obj:
                            sig_data = _extract_signature_object(obj, objnum)
                            results["signatures"].append(sig_data)
                except Exception as e:
                    logger.warning(f"Failed to extract signature object: {e}")
                    continue
                    
    except Exception as e:
        results["pikepdf_error"] = str(e)

    # Check with PyMuPDF for widget annotations (signature appearances)
    try:
        with fitz.open(pdf_path) as doc:
            for page_num, page in enumerate(doc):
                widgets = page.widgets()
                if widgets:
                    for widget in widgets:
                        if widget.field_type == fitz.PDF_WIDGET_TYPE_SIGNATURE:  # type: ignore[attr-defined] -- fitz.PDF_WIDGET_TYPE_SIGNATURE constant exists at runtime, stubs incomplete
                            widget_info = {
                                "page": page_num + 1,
                                "field_name": widget.field_name,
                                "field_type": "Signature",
                                "rect": list(widget.rect),
                                "field_value": widget.field_value,
                            }
                            results["signature_fields"].append(widget_info)
    except Exception as e:
        results["pymupdf_error"] = str(e)

    # Update summary
    results["signature_count"] = len(results["signatures"]) + len(results["signature_fields"])
    results["has_signatures"] = results["signature_count"] > 0
    
    return results  # type: ignore[return-value] -- results dict has dynamic keys like "error", "sig_flags", TypedDict allows extra keys at runtime


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _extract_fingerprints(pdf_path: str) -> dict:
    """Extract all fingerprints and unique identifiers from a PDF"""
    fingerprints = {
        "file_hashes": {},
        "pdf_ids": {},
        "xmp_uuids": {},
        "structure": {},
        "fonts": [],
        "content_hash": "",
    }
    
    # File hashes
    try:
        with open(pdf_path, 'rb') as f:
            content = f.read()
            fingerprints["file_hashes"] = {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
    except Exception as e:
        fingerprints["file_hashes"]["error"] = str(e)
    
    # PDF internal IDs and structure
    try:
        with pikepdf.open(pdf_path) as pdf:
            # Document IDs
            if '/ID' in pdf.trailer:
                doc_id = pdf.trailer['/ID']
                fingerprints["pdf_ids"] = {
                    "id_0": bytes(doc_id[0]).hex(),
                    "id_1": bytes(doc_id[1]).hex(),
                    "ids_match": bytes(doc_id[0]).hex() == bytes(doc_id[1]).hex(),
                }
            
            # XMP UUIDs
            if pdf.Root.get('/Metadata'):
                xmp = bytes(pdf.Root['/Metadata'].read_bytes()).decode('utf-8', errors='ignore')
                doc_ids = re.findall(r'DocumentID>uuid:([^<]+)<', xmp)
                inst_ids = re.findall(r'InstanceID>uuid:([^<]+)<', xmp)
                fingerprints["xmp_uuids"] = {
                    "document_id": doc_ids[0] if doc_ids else None,
                    "instance_id": inst_ids[0] if inst_ids else None,
                }
            
            # Structure fingerprint
            obj_types = {}
            for objnum in range(1, len(pdf.objects) + 1):
                try:
                    obj = pdf.get_object((objnum, 0))
                    if isinstance(obj, pikepdf.Dictionary):
                        obj_type = str(obj.get('/Type', 'Dictionary'))
                        obj_types[obj_type] = obj_types.get(obj_type, 0) + 1
                    elif isinstance(obj, pikepdf.Stream):
                        obj_types['Stream'] = obj_types.get('Stream', 0) + 1
                except Exception as e:
                    logger.warning(f"Operation failed: {e}")
            
            fingerprints["structure"] = {
                "pdf_version": str(pdf.pdf_version),
                "object_count": len(pdf.objects),
                "object_types": obj_types,
            }
            
            # Font fingerprint
            fonts = set()
            for page in pdf.pages:
                if '/Resources' in page:
                    res = page['/Resources']
                    if '/Font' in res:
                        for font_name, font_ref in res['/Font'].items():
                            try:
                                font_obj = font_ref.get_object() if hasattr(font_ref, 'get_object') else font_ref
                                base_font = str(font_obj.get('/BaseFont', 'Unknown'))
                                fonts.add(base_font)
                            except Exception as e:
                                logger.warning(f"Failed to extract font information: {e}")
            fingerprints["fonts"] = sorted(list(fonts))
            
    except Exception as e:
        fingerprints["pikepdf_error"] = str(e)
    
    # Content hash (text only - excludes metadata)
    try:
        with fitz.open(pdf_path) as doc:
            text_content = ''
            for page in doc:
                text_content += page.get_text()
            fingerprints["content_hash"] = hashlib.sha256(text_content.encode()).hexdigest()
            fingerprints["content_length"] = len(text_content)
    except Exception as e:
        fingerprints["content_error"] = str(e)
    
    return fingerprints


def _extract_signature_field(field_obj) -> dict:
    """Extract information from a signature field"""
    info = {
        "type": "signature_field",
    }
    
    try:
        # Field name
        if "/T" in field_obj:
            info["field_name"] = str(field_obj["/T"])
        
        # Signature value
        if "/V" in field_obj:
            sig_dict = field_obj["/V"]
            if isinstance(sig_dict, pikepdf.Dictionary):
                info.update(_extract_signature_dict(sig_dict))
    except Exception as e:
        info["extraction_error"] = str(e)
    
    return info


def _extract_signature_dict(sig_dict) -> dict:
    """Extract information from a signature dictionary"""
    info = {}
    
    try:
        # Filter (signature handler)
        if "/Filter" in sig_dict:
            info["filter"] = str(sig_dict["/Filter"])
        
        # SubFilter (signature format)
        if "/SubFilter" in sig_dict:
            info["sub_filter"] = str(sig_dict["/SubFilter"])
        
        # Signing time
        if "/M" in sig_dict:
            info["signing_time"] = str(sig_dict["/M"])
        
        # Signer name
        if "/Name" in sig_dict:
            info["signer_name"] = str(sig_dict["/Name"])
        
        # Location
        if "/Location" in sig_dict:
            info["location"] = str(sig_dict["/Location"])
        
        # Reason
        if "/Reason" in sig_dict:
            info["reason"] = str(sig_dict["/Reason"])
        
        # Contact info
        if "/ContactInfo" in sig_dict:
            info["contact_info"] = str(sig_dict["/ContactInfo"])
        
        # ByteRange (indicates signed content range)
        if "/ByteRange" in sig_dict:
            byte_range = sig_dict["/ByteRange"]
            info["byte_range"] = [int(x) for x in byte_range]
        
        # Contents (the actual signature - extract certificate info)
        if "/Contents" in sig_dict:
            contents = bytes(sig_dict["/Contents"])
            info["signature_size_bytes"] = len(contents)
            cert_info = _extract_certificate_info(contents)
            if cert_info:
                info["certificate"] = cert_info
                
    except Exception as e:
        info["extraction_error"] = str(e)
    
    return info


def _extract_signature_object(obj, objnum: int) -> dict:
    """Extract information from a signature object"""
    info = {
        "object_number": objnum,
        "type": "signature_object",
    }
    info.update(_extract_signature_dict(obj))
    return info


def _extract_certificate_info(pkcs7_data: bytes) -> Optional[dict]:
    """Extract certificate information from PKCS#7 signature data"""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.x509 import load_der_x509_certificate
        
        # Try to parse as PKCS#7
        # The signature content is typically DER-encoded PKCS#7
        # Skip null bytes padding
        data = pkcs7_data.lstrip(b'\x00').rstrip(b'\x00')
        
        if not data:
            return None
            
        # Try to find the certificate within PKCS#7 structure
        # Look for certificate sequence marker
        cert_info = {}
        
        try:
            # Attempt to load certificates from PKCS7
            certs = pkcs7.load_der_pkcs7_certificates(data)
            if certs:
                cert = certs[0]  # Primary signer certificate
                cert_info = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": cert.not_valid_before_utc.isoformat(),
                    "not_valid_after": cert.not_valid_after_utc.isoformat(),
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                }
                
                # Extract common name if available
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        cert_info["common_name"] = attr.value
                    if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                        cert_info["organization"] = attr.value
                        
                return cert_info
        except Exception as e:
            logger.warning(f"Failed to parse certificate: {e}")
            
        return None
        
    except Exception as e:
        return {"error": str(e)}




def main():
    import warnings
    warnings.warn(
        "Direct script execution is deprecated. Use 'python verify_signature.py <file>' or import from pdf_forensics.cli",
        DeprecationWarning,
        stacklevel=2
    )
    from pdf_forensics.cli import main_verify_signature
    main_verify_signature()


def _deprecated_main():
    if len(sys.argv) < 2:
        print("Usage: python verify_signature.py <pdf_file> [output.md]")
        print("\nVerifies digital signatures in PDF documents.")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    
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


if __name__ == "__main__":
    main()
