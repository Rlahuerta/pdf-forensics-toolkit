"""
PDF Forensics Toolkit - Constants Module

Centralized storage of known producers, suspicious online tools, and common legitimate producers.
"""

from typing import Final, Dict, List, Any

# Map of known PDF producers to their metadata
# Used to identify the software system that created a PDF
KNOWN_PRODUCERS: Final[Dict[str, Dict[str, str]]] = {
    "pdfsharp": {"system": "PDFsharp (.NET)", "type": "dynamic_generation", "platform": ".NET/C#"},
    "itext": {"system": "iText", "type": "dynamic_generation", "platform": "Java"},
    "reportlab": {"system": "ReportLab", "type": "dynamic_generation", "platform": "Python"},
    "fpdf": {"system": "FPDF", "type": "dynamic_generation", "platform": "PHP"},
    "tcpdf": {"system": "TCPDF", "type": "dynamic_generation", "platform": "PHP"},
    "wkhtmltopdf": {"system": "wkhtmltopdf", "type": "html_to_pdf", "platform": "WebKit"},
    "weasyprint": {"system": "WeasyPrint", "type": "html_to_pdf", "platform": "Python"},
    "puppeteer": {"system": "Puppeteer/Chrome", "type": "html_to_pdf", "platform": "Node.js"},
    "prince": {"system": "Prince XML", "type": "html_to_pdf", "platform": "C++"},
    "adobe acrobat": {"system": "Adobe Acrobat", "type": "desktop_creation", "platform": "Desktop"},
    "adobe experience manager": {"system": "Adobe Experience Manager Forms", "type": "enterprise_forms", "platform": "Java/Enterprise"},
    "designer": {"system": "Adobe LiveCycle Designer", "type": "enterprise_forms", "platform": "Enterprise"},
    "microsoft": {"system": "Microsoft Office", "type": "office_export", "platform": "Desktop"},
    "libreoffice": {"system": "LibreOffice", "type": "office_export", "platform": "Desktop"},
    "openoffice": {"system": "OpenOffice", "type": "office_export", "platform": "Desktop"},
    "chrome": {"system": "Chrome Print", "type": "browser_print", "platform": "Browser"},
    "firefox": {"system": "Firefox Print", "type": "browser_print", "platform": "Browser"},
    "safari": {"system": "Safari Print", "type": "browser_print", "platform": "Browser"},
    "quartz": {"system": "macOS Quartz", "type": "os_native", "platform": "macOS"},
    "cairo": {"system": "Cairo Graphics", "type": "dynamic_generation", "platform": "C/Multi"},
    "ghostscript": {"system": "Ghostscript", "type": "conversion", "platform": "PostScript"},
    "pdftk": {"system": "PDFtk", "type": "manipulation", "platform": "CLI"},
    "qpdf": {"system": "QPDF", "type": "manipulation", "platform": "CLI"},
}

# List of online PDF editors/generators that may indicate manipulation
# These are higher-risk producers because they have lower integrity controls
SUSPICIOUS_PRODUCERS: Final[List[str]] = [
    "ilovepdf", "smallpdf", "pdf24", "sejda", "pdfcandy",
    "online2pdf", "sodapdf", "pdf2go", "cleverpdf"
]

# List of common legitimate producers that don't add risk to integrity score
# These are widely used, reputable tools with strong integrity controls
COMMON_PRODUCERS: Final[List[str]] = [
    "microsoft print to pdf", "chrome", "firefox"
]
