"""
PDF Metadata Module for SHADOWSCOPE
Extracts catalog, info, embedded files, and JavaScript actions from PDF files using pypdf.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pypdf

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType


@dataclass
class PdfMetadataConfig(ModuleConfig):
    """Configuration for PDF Metadata module."""
    scan_javascript: bool = True
    extract_embedded_files: bool = True


class PdfMetadataModule(BaseModule):
    """Module for extracting metadata and embedded actions from PDF files."""

    MODULE_NAME = "pdf_metadata"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "file"
    MODULE_DESCRIPTION = "Extract catalog, document info, page count, embedded files, and JavaScript actions from PDF files using pypdf"
    MODULE_TARGET_TYPES = [TargetType.FILE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["pypdf"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: PdfMetadataConfig | None = None) -> None:
        super().__init__(config=config or PdfMetadataConfig())
        self.config: PdfMetadataConfig = self.config if isinstance(self.config, PdfMetadataConfig) else PdfMetadataConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target file path string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _clean_meta_key(key: str) -> str:
        """Remove leading slash from PDF metadata key."""
        if key.startswith("/"):
            return key[1:]
        return key

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute PDF metadata extraction on target file."""
        file_path = Path(target.strip())
        if not file_path.is_file():
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"File not found: {target}"
            )

        # Validate PDF magic bytes
        try:
            with open(file_path, "rb") as f:
                header = f.read(5)
                if not header.startswith(b"%PDF-"):
                    return ModuleResult(
                        target=target,
                        module=self.MODULE_NAME,
                        data={},
                        status="failed",
                        error="Invalid PDF file (missing %PDF- header magic bytes)"
                    )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Could not read target file: {str(e)}"
            )

        try:
            reader = pypdf.PdfReader(str(file_path))
            num_pages = len(reader.pages)
            is_encrypted = reader.is_encrypted

            # Extract document info metadata
            metadata: dict[str, Any] = {}
            if reader.metadata:
                for k, v in reader.metadata.items():
                    clean_k = self._clean_meta_key(str(k))
                    metadata[clean_k] = str(v) if v is not None else ""

            # Check embedded attachments
            attachments: list[dict[str, Any]] = []
            try:
                if hasattr(reader, "attachments") and reader.attachments:
                    for name, content_list in reader.attachments.items():
                        attachments.append({
                            "name": name,
                            "count": len(content_list)
                        })
            except Exception:
                pass

            # Scan for JavaScript and suspicious actions in catalog & pages
            js_findings: list[str] = []
            suspicious_actions: list[str] = []

            # Check root catalog dictionary
            try:
                trailer = reader.trailer
                root = trailer.get("/Root", {})
                if isinstance(root, dict):
                    if "/Names" in root and "/JavaScript" in root["/Names"]:
                        js_findings.append("Root catalog contains /Names /JavaScript dictionary")
                    if "/OpenAction" in root:
                        suspicious_actions.append("Root catalog contains /OpenAction trigger")
                    if "/AA" in root:
                        suspicious_actions.append("Root catalog contains /AA (Additional Actions)")
            except Exception:
                pass

            # Inspect page objects for JS / Launch triggers
            try:
                for i, page in enumerate(reader.pages):
                    page_obj = page.get_object()
                    if isinstance(page_obj, dict):
                        if "/AA" in page_obj:
                            suspicious_actions.append(f"Page {i+1} contains /AA action")
                        if "/JS" in page_obj or "/JavaScript" in page_obj:
                            js_findings.append(f"Page {i+1} contains embedded JavaScript action")

                    # Basic keyword scan in text / object representation
                    page_str = str(page_obj)
                    if "/JavaScript" in page_str or "/JS" in page_str:
                        if f"Page {i+1}" not in "".join(js_findings):
                            js_findings.append(f"Page {i+1} references JavaScript")
                    if "/Launch" in page_str:
                        suspicious_actions.append(f"Page {i+1} contains /Launch action")
            except Exception:
                pass

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "file_path": str(file_path),
                    "file_size": file_path.stat().st_size,
                    "num_pages": num_pages,
                    "is_encrypted": is_encrypted,
                    "metadata": metadata,
                    "has_metadata": bool(metadata),
                    "embedded_files": attachments,
                    "has_embedded_files": bool(attachments),
                    "javascript_found": bool(js_findings),
                    "javascript_findings": js_findings,
                    "suspicious_actions": suspicious_actions,
                    "pdf_version": reader.pdf_header if hasattr(reader, "pdf_header") else None,
                },
                status="success"
            )

        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Failed to extract PDF metadata: {str(e)}"
            )


pdf_metadata_module = PdfMetadataModule
