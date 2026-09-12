"""
Office Macro Analysis Module for SHADOWSCOPE
Analyzes Microsoft Office documents for OLE streams, VBA macros, AutoExec triggers, and obfuscated payloads.
"""

import math
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import olefile

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

AUTOEXEC_KEYWORDS = {
    "autoopen", "autoexec", "document_open", "workbook_open",
    "autoclose", "document_close", "document_beforeclose",
    "autoexit", "autonew", "workbook_activate"
}

SUSPICIOUS_KEYWORDS = {
    "shell", "wscript.shell", "createobject", "powershell", "cmd.exe",
    "urldownloadtofile", "virtualalloc", "writeprocessmemory",
    "regwrite", "callbyname", "environ", "settimer", "executionpolicy",
    "xmlhttp", "winhttprequest", "base64", "xor", "strreverse"
}


@dataclass
class OfficeMacroAnalysisConfig(ModuleConfig):
    """Configuration for Office Macro Analysis module."""
    check_entropy: bool = True
    entropy_threshold: float = 6.5


class OfficeMacroAnalysisModule(BaseModule):
    """Module for analyzing Office documents for VBA macros, OLE streams, and AutoExec triggers."""

    MODULE_NAME = "office_macro_analysis"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "file"
    MODULE_DESCRIPTION = "Analyze Office documents for VBA macros, OLE streams, AutoExec triggers, and high entropy payloads"
    MODULE_TARGET_TYPES = [TargetType.FILE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["olefile"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: OfficeMacroAnalysisConfig | None = None) -> None:
        super().__init__(config=config or OfficeMacroAnalysisConfig())
        self.config: OfficeMacroAnalysisConfig = self.config if isinstance(self.config, OfficeMacroAnalysisConfig) else OfficeMacroAnalysisConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target file path string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def _scan_stream_text(data: bytes) -> tuple[set[str], set[str]]:
        """Scan raw bytes for AutoExec and suspicious keywords."""
        found_autoexec = set()
        found_suspicious = set()

        text_lower = data.lower().decode("latin1", errors="ignore")

        for kw in AUTOEXEC_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                found_autoexec.add(kw)

        for kw in SUSPICIOUS_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                found_suspicious.add(kw)

        return found_autoexec, found_suspicious

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute Office macro analysis on target file."""
        file_path = Path(target.strip())
        if not file_path.is_file():
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"File not found: {target}"
            )

        is_ole = olefile.isOleFile(str(file_path))
        is_zip = zipfile.is_zipfile(str(file_path))

        if not is_ole and not is_zip:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "file_path": str(file_path),
                    "file_size": file_path.stat().st_size,
                    "is_ole": False,
                    "is_openxml": False,
                    "has_macros": False,
                    "risk_score": 0,
                    "risk_level": "clean",
                    "summary": "File is neither OLE compound format nor OpenXML ZIP document."
                },
                status="success"
            )

        has_macros = False
        found_autoexec: set[str] = set()
        found_suspicious: set[str] = set()
        streams_info: list[dict[str, Any]] = []
        max_entropy = 0.0

        try:
            # 1. Process OLE compound document (.doc, .xls, .ppt, etc.)
            if is_ole:
                ole = olefile.OleFileIO(str(file_path))
                stream_list = ole.listdir()

                for path_parts in stream_list:
                    stream_path = "/".join(path_parts)
                    try:
                        stream_bytes = ole.openstream(path_parts).read()
                        ent = self._calc_entropy(stream_bytes)
                        max_entropy = max(max_entropy, ent)

                        if any(vba_kw in stream_path.lower() for vba_kw in ["vba", "macros", "_vba_project", "dir"]):
                            has_macros = True

                        auto_kws, susp_kws = self._scan_stream_text(stream_bytes)
                        if auto_kws or susp_kws:
                            has_macros = True
                            found_autoexec.update(auto_kws)
                            found_suspicious.update(susp_kws)

                        streams_info.append({
                            "name": stream_path,
                            "size": len(stream_bytes),
                            "entropy": ent
                        })
                    except Exception:
                        pass
                ole.close()

            # 2. Process OpenXML document (.docm, .xlsm, .pptm, .docx, etc.)
            elif is_zip:
                with zipfile.ZipFile(str(file_path), "r") as zf:
                    for name in zf.namelist():
                        if "vbaProject.bin" in name.lower() or "macros" in name.lower():
                            has_macros = True
                            vba_bytes = zf.read(name)
                            ent = self._calc_entropy(vba_bytes)
                            max_entropy = max(max_entropy, ent)

                            auto_kws, susp_kws = self._scan_stream_text(vba_bytes)
                            found_autoexec.update(auto_kws)
                            found_suspicious.update(susp_kws)

                            streams_info.append({
                                "name": name,
                                "size": len(vba_bytes),
                                "entropy": ent
                            })

            # Calculate risk score (0 to 100)
            risk_score = 0
            if has_macros:
                risk_score += 30
            if found_autoexec:
                risk_score += 35
            if found_suspicious:
                risk_score += min(25, len(found_suspicious) * 10)
            if max_entropy > self.config.entropy_threshold:
                risk_score += 10

            risk_score = min(100, risk_score)

            if risk_score >= 80:
                risk_level = "critical"
            elif risk_score >= 50:
                risk_level = "high"
            elif risk_score >= 25:
                risk_level = "medium"
            elif risk_score > 0:
                risk_level = "low"
            else:
                risk_level = "clean"

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "file_path": str(file_path),
                    "file_size": file_path.stat().st_size,
                    "is_ole": is_ole,
                    "is_openxml": is_zip,
                    "has_macros": has_macros,
                    "autoexec_keywords": sorted(list(found_autoexec)),
                    "suspicious_keywords": sorted(list(found_suspicious)),
                    "max_stream_entropy": max_entropy,
                    "streams_analyzed": len(streams_info),
                    "streams": streams_info[:20],  # limit to top 20 streams
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "summary": f"Office macro analysis: has_macros={has_macros}, risk_score={risk_score}/100 ({risk_level})"
                },
                status="success"
            )

        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Failed to analyze Office document: {str(e)}"
            )


office_macro_analysis_module = OfficeMacroAnalysisModule
