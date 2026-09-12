"""
File OSINT Modules for SHADOWSCOPE
"""

from .exif_extractor import ExifExtractorModule, exif_extractor_module
from .office_macro_analysis import OfficeMacroAnalysisModule, office_macro_analysis_module
from .pdf_metadata import PdfMetadataModule, pdf_metadata_module
from .steg_detect import StegDetectModule, steg_detect_module

__all__ = [
    "ExifExtractorModule",
    "exif_extractor_module",
    "PdfMetadataModule",
    "pdf_metadata_module",
    "StegDetectModule",
    "steg_detect_module",
    "OfficeMacroAnalysisModule",
    "office_macro_analysis_module",
]
