"""
PDF Document context manager for efficient resource management.

Opens PDF files once per library (fitz, pikepdf, pypdf) and caches the handles,
reducing repeated file I/O from 8-10 opens per analysis to 1-2 per library.
"""

from pathlib import Path
from typing import Optional

import fitz
import pikepdf
from pypdf import PdfReader

from pdf_forensics.limits import validate_pdf_file


class PDFDocument:
    """Context manager that opens a PDF once and provides shared library handles.

    Usage:
        with PDFDocument("document.pdf") as pdf:
            text = pdf.fitz_doc[0].get_text()
            obj = pdf.pikepdf_doc.Root
            reader = pdf.pypdf_reader

    Handles are lazily opened on first access and cleaned up on exit.
    """

    def __init__(self, path: str):
        self.path = path
        self._fitz_doc: Optional[fitz.Document] = None
        self._pikepdf_doc: Optional[pikepdf.Pdf] = None
        self._pypdf_reader: Optional[PdfReader] = None

    def __enter__(self):
        is_valid, error = validate_pdf_file(self.path)
        if not is_valid:
            raise ValueError(error)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    @property
    def fitz_doc(self) -> fitz.Document:
        """Lazily open and return a PyMuPDF document handle."""
        if self._fitz_doc is None:
            self._fitz_doc = fitz.open(self.path)
        return self._fitz_doc

    @property
    def pikepdf_doc(self) -> pikepdf.Pdf:
        """Lazily open and return a pikepdf document handle."""
        if self._pikepdf_doc is None:
            self._pikepdf_doc = pikepdf.open(self.path)
        return self._pikepdf_doc

    @property
    def pypdf_reader(self) -> PdfReader:
        """Lazily open and return a pypdf reader."""
        if self._pypdf_reader is None:
            self._pypdf_reader = PdfReader(self.path)
        return self._pypdf_reader

    def close(self):
        """Close all opened document handles."""
        if self._fitz_doc is not None:
            self._fitz_doc.close()
            self._fitz_doc = None
        if self._pikepdf_doc is not None:
            self._pikepdf_doc.close()
            self._pikepdf_doc = None
        # pypdf PdfReader has no explicit close method
        self._pypdf_reader = None