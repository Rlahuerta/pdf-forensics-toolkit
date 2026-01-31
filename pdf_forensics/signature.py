#!/usr/bin/env python3
"""
Real PDF signature validation using pyHanko library.

Provides cryptographic verification of PDF digital signatures,
including signature validity, document integrity, and certificate chain validation.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from pdf_forensics.logging_config import get_logger

logger = get_logger(__name__)

try:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import (
        validate_pdf_signature,
        SignatureCoverageLevel,
        ValidationContext,
    )
    from pyhanko_certvalidator.validate import ValidationError
    PYHANKO_AVAILABLE = True
except ImportError as e:
    logger.warning(f"pyHanko not available: {e}")
    PYHANKO_AVAILABLE = False


def validate_signature(pdf_path: str, trust_roots: Optional[List[str]] = None) -> dict:
    """
    Validate digital signatures in a PDF document using pyHanko.
    
    Args:
        pdf_path: Path to the PDF file
        trust_roots: Optional list of paths to trusted root certificates (PEM format)
    
    Returns:
        Dictionary containing:
        - signature_valid: bool - True if all signatures are cryptographically valid
        - intact: bool - True if document hasn't been modified since signing
        - signature_count: int - Number of signatures found
        - signatures: list - Detailed information about each signature
        - certificate_chain: list - Certificate chain details (if available)
        - validation_errors: list - Any errors encountered during validation
        - has_signatures: bool - Whether the document has any signatures
    """
    result = {
        "file": Path(pdf_path).name,
        "file_path": pdf_path,
        "validation_time": datetime.now().isoformat(),
        "signature_valid": False,
        "intact": False,
        "signature_count": 0,
        "signatures": [],
        "certificate_chain": [],
        "validation_errors": [],
        "has_signatures": False,
    }
    
    if not PYHANKO_AVAILABLE:
        result["validation_errors"].append({
            "error": "pyHanko not available",
            "detail": "Install pyHanko to enable signature validation"
        })
        return result
    
    path = Path(pdf_path)
    if not path.exists():
        result["validation_errors"].append({
            "error": "File not found",
            "detail": f"File does not exist: {pdf_path}"
        })
        return result
    
    try:
        with open(pdf_path, 'rb') as f:
            reader = PdfFileReader(f)
            
            sig_fields = reader.root.get('/AcroForm', {}).get('/Fields', [])
            
            if not sig_fields:
                result["has_signatures"] = False
                result["signature_count"] = 0
                return result
            
            signature_fields = []
            for field in sig_fields:
                try:
                    field_obj = field.get_object() if hasattr(field, 'get_object') else field
                    if field_obj.get('/FT') == '/Sig':
                        signature_fields.append(field_obj)
                except Exception as e:
                    logger.warning(f"Failed to check field type: {e}")
                    continue
            
            if not signature_fields:
                result["has_signatures"] = False
                result["signature_count"] = 0
                return result
            
            result["has_signatures"] = True
            result["signature_count"] = len(signature_fields)
            
            vc = None
            if trust_roots:
                try:
                    from pyhanko_certvalidator import ValidationContext as CertValidationContext
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    trust_certs = []
                    for cert_path in trust_roots:
                        with open(cert_path, 'rb') as cert_file:
                            cert_data = cert_file.read()
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                            trust_certs.append(cert)
                    
                    if trust_certs:
                        vc = CertValidationContext(trust_roots=trust_certs)
                except Exception as e:
                    result["validation_errors"].append({
                        "error": "Failed to load trust roots",
                        "detail": str(e)
                    })
            
            all_valid = True
            all_intact = True
            
            for idx, sig_field in enumerate(signature_fields):
                sig_info = _validate_signature_field(reader, sig_field, idx, vc)
                result["signatures"].append(sig_info)
                
                if not sig_info.get("valid", False):
                    all_valid = False
                if not sig_info.get("intact", False):
                    all_intact = False
                
                if sig_info.get("errors"):
                    result["validation_errors"].extend(sig_info["errors"])
                
                if idx == 0 and sig_info.get("certificate_chain"):
                    result["certificate_chain"] = sig_info["certificate_chain"]
            
            result["signature_valid"] = all_valid and result["signature_count"] > 0
            result["intact"] = all_intact and result["signature_count"] > 0
            
    except Exception as e:
        logger.error(f"Failed to validate signatures: {e}")
        result["validation_errors"].append({
            "error": "Validation failed",
            "detail": str(e),
            "exception_type": type(e).__name__
        })
    
    return result


def _validate_signature_field(
    reader: 'PdfFileReader',
    sig_field: Any,
    index: int,
    validation_context: Optional[Any] = None
) -> dict:
    """
    Validate a single signature field.
    
    Args:
        reader: PyHanko PdfFileReader instance
        sig_field: Signature field object
        index: Index of this signature
        validation_context: Optional validation context for certificate validation
    
    Returns:
        Dictionary with signature validation details
    """
    sig_info = {
        "index": index,
        "field_name": "",
        "valid": False,
        "intact": False,
        "coverage": "",
        "signer": "",
        "signing_time": "",
        "errors": [],
        "certificate_chain": [],
    }
    
    try:
        if '/T' in sig_field:
            sig_info["field_name"] = str(sig_field['/T'])
        
        if '/V' not in sig_field:
            sig_info["errors"].append({
                "error": "No signature value",
                "detail": "Signature field has no /V entry"
            })
            return sig_info
        
        sig_dict = sig_field['/V']
        
        if '/Name' in sig_dict:
            sig_info["signer"] = str(sig_dict['/Name'])
        if '/M' in sig_dict:
            sig_info["signing_time"] = str(sig_dict['/M'])
        
        try:
            sig_obj = reader.embedded_signatures[index] if index < len(reader.embedded_signatures) else None
            
            if not sig_obj:
                sig_info["errors"].append({
                    "error": "Signature object not found",
                    "detail": f"No embedded signature at index {index}"
                })
                return sig_info
            
            validation_result = validate_pdf_signature(
                sig_obj,
                validation_context=validation_context
            )
            
            sig_info["valid"] = validation_result.valid
            sig_info["intact"] = validation_result.intact
            sig_info["coverage"] = str(validation_result.coverage)
            
            if hasattr(validation_result, 'signer_info') and validation_result.signer_info:
                signer = validation_result.signer_info
                if hasattr(signer, 'subject'):
                    sig_info["signer"] = signer.subject.rfc4514_string()
            
            if hasattr(validation_result, 'signer_cert') and validation_result.signer_cert:
                cert = validation_result.signer_cert
                cert_info = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": cert.not_valid_before_utc.isoformat(),
                    "not_valid_after": cert.not_valid_after_utc.isoformat(),
                }
                sig_info["certificate_chain"].append(cert_info)
            
            if hasattr(validation_result, 'validation_errors'):
                for error in validation_result.validation_errors:
                    sig_info["errors"].append({
                        "error": "Validation error",
                        "detail": str(error)
                    })
            
        except ValidationError as e:
            sig_info["errors"].append({
                "error": "Certificate validation failed",
                "detail": str(e)
            })
        except Exception as e:
            sig_info["errors"].append({
                "error": "Signature validation failed",
                "detail": str(e),
                "exception_type": type(e).__name__
            })
    
    except Exception as e:
        logger.error(f"Failed to process signature field {index}: {e}")
        sig_info["errors"].append({
            "error": "Field processing failed",
            "detail": str(e),
            "exception_type": type(e).__name__
        })
    
    return sig_info


def is_pyhanko_available() -> bool:
    """Check if pyHanko is available for signature validation."""
    return PYHANKO_AVAILABLE
