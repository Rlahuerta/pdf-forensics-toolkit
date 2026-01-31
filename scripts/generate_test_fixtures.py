#!/usr/bin/env python3
"""
PDF Forensics Toolkit - Test Fixture Generator

Generates comprehensive test PDFs covering:
- Digital signatures (valid, invalid, expired)
- Security threats (JavaScript, launch actions, embedded files, URI)
- Hidden content (OCG layers, invisible text, hidden annotations)
- Diverse creators (Adobe, Chrome, MS Word, iText, PDFsharp, LibreOffice)
- Tampering patterns (orphan objects, shadow attacks)

Usage:
    python scripts/generate_test_fixtures.py

Dependencies:
    PyMuPDF (fitz), pikepdf, pyHanko, cryptography
"""

from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime
import fitz
import pikepdf
import os
from pathlib import Path


def generate_signed_valid_pdf(output_path: str):
    """Create PDF with valid self-signed signature"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This PDF has a valid self-signed signature.", fontsize=12)
    page.insert_text((100, 130), "Generated for PDF forensics toolkit testing.", fontsize=10)
    
    doc.set_metadata({
        'creator': 'PDF Forensics Test Generator',
        'producer': 'PyMuPDF + pyHanko',
        'title': 'Valid Signed Test Document',
        'author': 'Test Suite'
    })
    
    temp_path = output_path.replace('.pdf', '_unsigned.pdf')
    doc.save(temp_path)
    doc.close()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Test City"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "PDF Forensics Toolkit"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Signer"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    cms_signer = signers.SimpleSigner(
        signing_cert=cert,
        signing_key=private_key,
        cert_registry=None
    )
    
    with open(temp_path, 'rb') as doc_file:
        w = IncrementalPdfFileWriter(doc_file)
        out = signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Signature1',
                reason='Testing PDF forensics toolkit',
                location='Test Environment'
            ),
            signer=cms_signer
        )
        
        with open(output_path, 'wb') as f_out:
            f_out.write(out.getvalue())
    
    # Clean up temp file
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    return output_path


def generate_signed_invalid_pdf(input_signed_pdf: str, output_path: str):
    """Modify a signed PDF to break the signature"""
    
    if not Path(input_signed_pdf).exists():
        print(f"⚠️  Skipping {output_path} - input not found: {input_signed_pdf}")
        return None
    
    # Open the signed PDF
    with pikepdf.open(input_signed_pdf) as pdf:
        # Tamper with content (adds annotation)
        page = pdf.pages[0]
        
        # Create a new annotation (this breaks the signature)
        annot = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Annot'),
            '/Subtype': pikepdf.Name('/FreeText'),
            '/Rect': [200, 200, 400, 250],
            '/Contents': pikepdf.String('TAMPERED: Amount changed to $10,000'),
            '/C': [1, 0, 0],  # Red color
            '/CA': 1.0,  # Opacity
        })
        
        # Add annotation to page
        if '/Annots' not in page:
            page['/Annots'] = pikepdf.Array()
        page['/Annots'].append(pdf.make_indirect(annot))
        
        # Save (this breaks the signature)
        pdf.save(output_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Signature is now INVALID due to post-signing modification")
    return output_path


def generate_signed_expired_pdf(output_path: str):
    """Create PDF signed with expired certificate"""
    
    # Create base PDF
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This PDF has an EXPIRED certificate.", fontsize=12)
    
    temp_path = output_path.replace('.pdf', '_unsigned.pdf')
    doc.save(temp_path)
    doc.close()
    
    # Generate certificate that expired yesterday
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Expired Signer"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=2))
        .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    
    # Sign with expired cert
    cms_signer = signers.SimpleSigner(
        signing_cert=cert,
        signing_key=private_key,
        cert_registry=None
    )
    
    with open(temp_path, 'rb') as doc_file:
        w = IncrementalPdfFileWriter(doc_file)
        out = signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='Signature1'),
            signer=cms_signer
        )
        
        with open(output_path, 'wb') as f_out:
            f_out.write(out.getvalue())
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Certificate expired 1 day ago")
    return output_path


def generate_javascript_pdf(output_path: str):
    """Create PDF with embedded JavaScript"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "⚠️ This PDF contains JavaScript", fontsize=14, color=(1, 0, 0))
    page.insert_text((100, 130), "Security Risk: High", fontsize=10)
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        js_code = """
        app.alert({
            cMsg: 'This PDF contains JavaScript!',
            nIcon: 2,
            cTitle: 'Security Warning'
        });
        """
        
        pdf.Root.OpenAction = pikepdf.Dictionary({
            '/S': pikepdf.Name('/JavaScript'),
            '/JS': pikepdf.String(js_code)
        })
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains JavaScript (security risk)")
    return output_path


def generate_launch_action_pdf(output_path: str):
    """Create PDF with launch action (can execute external programs)"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "⚠️ This PDF has a Launch Action", fontsize=14, color=(1, 0, 0))
    page.insert_text((100, 130), "Could execute external programs!", fontsize=10)
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        pdf.Root.OpenAction = pikepdf.Dictionary({
            '/S': pikepdf.Name('/Launch'),
            '/F': pikepdf.String('malicious.exe'),
            '/Win': pikepdf.Dictionary({
                '/F': pikepdf.String('C:\\\\Windows\\\\System32\\\\calc.exe'),
                '/P': pikepdf.String('')
            })
        })
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains Launch Action (CRITICAL security risk)")
    return output_path


def generate_embedded_file_pdf(output_path: str):
    """Create PDF with embedded executable file"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This PDF contains an embedded file", fontsize=12)
    page.insert_text((100, 130), "📎 attachment.exe (hidden)", fontsize=10, color=(0.5, 0.5, 0.5))
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        fake_exe_content = b'MZ\x90\x00' + b'\x00' * 100
        
        embedded_file_stream = pikepdf.Stream(pdf, fake_exe_content)
        embedded_file_stream['/Type'] = pikepdf.Name('/EmbeddedFile')
        embedded_file_stream['/Subtype'] = pikepdf.Name('/application/x-msdownload')
        
        filespec = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Filespec'),
            '/F': pikepdf.String('malicious.exe'),
            '/UF': pikepdf.String('malicious.exe'),
            '/EF': pikepdf.Dictionary({
                '/F': embedded_file_stream
            })
        })
        
        pdf.Root.Names = pikepdf.Dictionary({
            '/EmbeddedFiles': pikepdf.Dictionary({
                '/Names': pikepdf.Array([
                    pikepdf.String('malicious.exe'),
                    filespec
                ])
            })
        })
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains embedded file (potential malware)")
    return output_path


def generate_uri_action_pdf(output_path: str):
    """Create PDF with automatic redirect to external URL"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "This PDF redirects to an external URL", fontsize=12)
    page.insert_text((100, 130), "🔗 http://malicious-site.example.com", fontsize=10, color=(0, 0, 1))
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        pdf.Root.OpenAction = pikepdf.Dictionary({
            '/S': pikepdf.Name('/URI'),
            '/URI': pikepdf.String('http://malicious-phishing-site.example.com/steal-credentials')
        })
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains URI action (phishing risk)")
    return output_path


def generate_hidden_layer_pdf(output_path: str):
    """Create PDF with hidden text annotation"""
    
    doc = fitz.open()
    page = doc.new_page()
    
    page.insert_text((100, 100), "Visible Text: Invoice Total $100", fontsize=12)
    
    annot = page.add_text_annot((200, 100), "Hidden: ACTUAL Total $10,000")
    annot.set_flags(2)
    annot.set_colors({"stroke": [1, 0, 0]})
    
    doc.set_metadata({'creator': 'PDF Forensics Test Generator', 'title': 'Hidden Content Test'})
    doc.save(output_path)
    doc.close()
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains hidden text annotation")
    return output_path


def generate_invisible_text_pdf(output_path: str):
    """Create PDF with invisible text using rendering mode 3"""
    
    doc = fitz.open()
    page = doc.new_page()
    
    page.insert_text((100, 100), "Visible: Standard invoice for $100", fontsize=12)
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        page = pdf.pages[0]
        
        if '/Resources' not in page:
            page['/Resources'] = pikepdf.Dictionary()
        if '/Font' not in page.Resources:
            page.Resources['/Font'] = pikepdf.Dictionary()
        
        page.Resources.Font['/F1'] = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Font'),
            '/Subtype': pikepdf.Name('/Type1'),
            '/BaseFont': pikepdf.Name('/Helvetica')
        })
        
        invisible_content = b"""
        BT
        /F1 12 Tf
        100 150 Td
        3 Tr
        (HIDDEN: This invoice has been altered. Real amount: $10,000) Tj
        ET
        """
        
        if '/Contents' in page:
            existing_contents = page.Contents
            if isinstance(existing_contents, pikepdf.Array):
                new_stream = pikepdf.Stream(pdf, invisible_content)
                existing_contents.append(new_stream)
            else:
                existing = existing_contents.read_bytes()
                new_content = existing + b'\n' + invisible_content
                page.Contents = pikepdf.Stream(pdf, new_content)
        else:
            page.Contents = pikepdf.Stream(pdf, invisible_content)
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains invisible text (Tr=3 rendering mode)")
    return output_path


def generate_hidden_annotations_pdf(output_path: str):
    """Create PDF with hidden/invisible annotations"""
    
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((100, 100), "Document with hidden annotations", fontsize=12)
    
    temp_path = output_path.replace('.pdf', '_temp.pdf')
    doc.save(temp_path)
    doc.close()
    
    with pikepdf.open(temp_path) as pdf:
        page = pdf.pages[0]
        
        hidden_annot = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Annot'),
            '/Subtype': pikepdf.Name('/Text'),
            '/Rect': [200, 200, 220, 220],
            '/Contents': pikepdf.String('SECRET: This document was forged'),
            '/F': 2,  # Hidden flag
            '/T': pikepdf.String('Forger'),
            '/C': [1, 0, 0]
        })
        
        invisible_annot = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Annot'),
            '/Subtype': pikepdf.Name('/FreeText'),
            '/Rect': [100, 300, 400, 350],
            '/Contents': pikepdf.String('The signatory did not actually approve this'),
            '/F': 6,  # Hidden + Print flag
            '/DA': pikepdf.String('/Helvetica 12 Tf 1 0 0 rg'),
            '/CA': 0.0
        })
        
        if '/Annots' not in page:
            page['/Annots'] = pikepdf.Array()
        
        page['/Annots'].append(pdf.make_indirect(hidden_annot))
        page['/Annots'].append(pdf.make_indirect(invisible_annot))
        
        pdf.save(output_path)
    
    os.remove(temp_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains 2 hidden/invisible annotations")
    return output_path


def generate_creator_pdfs(output_dir: str = 'tests/fixtures'):
    """Generate PDFs with diverse creator metadata"""
    
    CREATOR_PATTERNS = [
        {
            'name': 'adobe',
            'creator': 'Adobe Acrobat Pro DC 2023.008.20470',
            'producer': 'Adobe PDF Library 17.011',
            'title': 'Contract Agreement',
            'author': 'John Smith'
        },
        {
            'name': 'chrome',
            'creator': 'Chromium',
            'producer': 'Skia/PDF m119',
            'title': 'Web Page Print',
            'author': ''
        },
        {
            'name': 'msword',
            'creator': 'Microsoft® Word for Microsoft 365',
            'producer': 'Microsoft® Word for Microsoft 365',
            'title': 'Report Document',
            'author': 'Microsoft Office User'
        },
        {
            'name': 'itext',
            'creator': 'iText® 7.2.5 ©2000-2024 Apryse Group NV',
            'producer': 'iText® 7.2.5 ©2000-2024 Apryse Group NV',
            'title': 'Generated Invoice',
            'author': 'Automated System'
        },
        {
            'name': 'pdfsharp',
            'creator': 'PDFsharp 1.50.5147 (www.pdfsharp.com)',
            'producer': 'PDFsharp 1.50.5147 (www.pdfsharp.com)',
            'title': '.NET Generated PDF',
            'author': 'PDFsharp Application'
        },
        {
            'name': 'libreoffice',
            'creator': 'Writer',
            'producer': 'LibreOffice 7.6',
            'title': 'Open Source Document',
            'author': 'LibreOffice User'
        }
    ]
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    for i, pattern in enumerate(CREATOR_PATTERNS, 1):
        doc = fitz.open()
        page = doc.new_page()
        
        page.insert_text(
            (100, 100),
            f"Document created by: {pattern['name'].upper()}",
            fontsize=14,
            fontname="helv"
        )
        page.insert_text((100, 130), f"Creator: {pattern['creator']}", fontsize=10)
        page.insert_text((100, 150), f"Producer: {pattern['producer']}", fontsize=10)
        
        page.insert_text((100, 200), "Sample Content:", fontsize=12)
        page.insert_text((100, 220), "This is a test document generated to simulate", fontsize=10)
        page.insert_text((100, 240), f"PDFs created by {pattern['name']} software.", fontsize=10)
        
        doc.set_metadata({
            'creator': pattern['creator'],
            'producer': pattern['producer'],
            'title': pattern['title'],
            'author': pattern['author']
        })
        
        filename = f"creator_{i:02d}_{pattern['name']}_test.pdf"
        filepath = output_path / filename
        doc.save(str(filepath))
        doc.close()
        
        print(f"✅ Created: {filepath}")
    
    print(f"\n✅ Generated {len(CREATOR_PATTERNS)} creator pattern PDFs")
    return len(CREATOR_PATTERNS)


def generate_orphan_objects_pdf(output_path: str):
    """Create PDF with many orphan (unreferenced) objects"""
    
    pdf = pikepdf.new()
    
    page = pdf.add_blank_page(page_size=(612, 792))
    
    content = b"""
    BT
    /F1 12 Tf
    100 700 Td
    (This PDF contains deleted content as orphan objects) Tj
    ET
    """
    
    page.Resources = pikepdf.Dictionary({
        '/Font': pikepdf.Dictionary({
            '/F1': pikepdf.Dictionary({
                '/Type': pikepdf.Name('/Font'),
                '/Subtype': pikepdf.Name('/Type1'),
                '/BaseFont': pikepdf.Name('/Helvetica')
            })
        })
    })
    
    page.Contents = pikepdf.Stream(pdf, content)
    
    for i in range(15):
        orphan_stream = pikepdf.Stream(pdf, f"""
        BT
        /F1 12 Tf
        100 {600 - i*20} Td
        (DELETED LINE {i+1}: This was removed but still exists in file) Tj
        ET
        """.encode())
        pdf.make_indirect(orphan_stream)
    
    for i in range(5):
        orphan_font = pikepdf.Dictionary({
            '/Type': pikepdf.Name('/Font'),
            '/Subtype': pikepdf.Name('/Type1'),
            '/BaseFont': pikepdf.Name(f'/OrphanFont{i}')
        })
        pdf.make_indirect(orphan_font)
    
    pdf.save(output_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains 20+ orphan objects (indicates deleted content)")
    return output_path


def generate_shadow_attack_pdf(output_path: str):
    """Create PDF with shadow attack pattern (multiple content streams)"""
    
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    
    page.Resources = pikepdf.Dictionary({
        '/Font': pikepdf.Dictionary({
            '/F1': pikepdf.Dictionary({
                '/Type': pikepdf.Name('/Font'),
                '/Subtype': pikepdf.Name('/Type1'),
                '/BaseFont': pikepdf.Name('/Helvetica')
            })
        })
    })
    
    visible_content = pikepdf.Stream(pdf, b"""
    BT
    /F1 14 Tf
    100 700 Td
    (Invoice Amount: $100.00) Tj
    ET
    
    100 650 200 50 re
    S
    """)
    
    hidden_content = pikepdf.Stream(pdf, b"""
    1 1 1 rg
    95 695 250 20 re
    f
    
    BT
    /F1 14 Tf
    1 0 0 rg
    100 700 Td
    (Invoice Amount: $10,000.00) Tj
    ET
    """)
    
    overlay_content = pikepdf.Stream(pdf, b"""
    BT
    /F1 8 Tf
    0.5 0.5 0.5 rg
    100 680 Td
    (Original amount was modified) Tj
    ET
    """)
    
    page.Contents = pikepdf.Array([
        visible_content,
        hidden_content,
        overlay_content
    ])
    
    pdf.save(output_path)
    
    print(f"✅ Created: {output_path}")
    print(f"   ⚠️  Contains 3 content streams (shadow attack pattern)")
    return output_path


if __name__ == '__main__':
    print("This module contains generation functions.")
    print("Run generate_all_test_fixtures.py to create all PDFs.")
