"""
Firmware Scanner Module for SHADOWSCOPE
Scans binary firmware images for embedded file system headers, hardcoded keys, and password hashes.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# File system and compression magic headers
FILE_SYSTEM_SIGNATURES: list[dict[str, Any]] = [
    {"name": "SquashFS", "magic": b"hsqs", "desc": "SquashFS little endian file system"},
    {"name": "SquashFS (big endian)", "magic": b"sqsh", "desc": "SquashFS big endian file system"},
    {"name": "CramFS", "magic": b"\x28\xcd\x3d\x45", "desc": "CramFS file system"},
    {"name": "JFFS2", "magic": b"\x85\x19", "desc": "JFFS2 file system"},
    {"name": "U-Boot Header", "magic": b"\x27\x05\x19\x56", "desc": "U-Boot image header"},
    {"name": "TRX Firmware", "magic": b"HDR0", "desc": "TRX firmware header"},
    {"name": "ELF Executable", "magic": b"\x7fELF", "desc": "ELF binary file"},
    {"name": "GZIP Archive", "magic": b"\x1f\x8b\x08", "desc": "GZIP compressed archive"},
    {"name": "Zip Archive", "magic": b"PK\x03\x04", "desc": "ZIP archive"},
    {"name": "LZMA Stream", "magic": b"\x5d\x00\x00", "desc": "LZMA compressed stream"},
]


@dataclass
class FirmwareScannerConfig(ModuleConfig):
    """Configuration for Firmware Scanner module."""
    scan_secrets: bool = True
    max_scan_bytes: int = 10 * 1024 * 1024  # 10MB limit for fast scan


class FirmwareScannerModule(BaseModule):
    """Module for scanning embedded firmware binaries for file systems and hardcoded credentials/keys."""

    MODULE_NAME = "firmware_scanner"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "iot"
    MODULE_DESCRIPTION = "Scan binary firmware images for embedded SquashFS/JFFS2 file systems, hardcoded private keys, and password hashes"
    MODULE_TARGET_TYPES = [TargetType.FILE, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = []
    MODULE_TIMEOUT = 300

    def __init__(self, config: FirmwareScannerConfig | None = None) -> None:
        super().__init__(config=config or FirmwareScannerConfig())
        self.config: FirmwareScannerConfig = self.config if isinstance(self.config, FirmwareScannerConfig) else FirmwareScannerConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target file path string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute firmware binary scan."""
        file_path = Path(target.strip())
        if not file_path.is_file():
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Firmware file not found: {target}"
            )

        max_bytes = int(getattr(self.config, "max_scan_bytes", 10 * 1024 * 1024))

        try:
            with open(file_path, "rb") as f:
                content = f.read(max_bytes)

            header_matches: list[dict[str, Any]] = []
            for sig in FILE_SYSTEM_SIGNATURES:
                offset = 0
                magic = sig["magic"]
                while True:
                    pos = content.find(magic, offset)
                    if pos == -1:
                        break
                    header_matches.append({
                        "name": sig["name"],
                        "description": sig["desc"],
                        "offset": pos,
                        "offset_hex": f"0x{pos:X}"
                    })
                    offset = pos + len(magic)
                    if len(header_matches) >= 30:  # cap matches
                        break

            # Scan text content for potential secrets / hashes
            secrets_found: list[dict[str, Any]] = []
            text = content.decode("latin1", errors="ignore")

            # Check SSH private keys
            if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
                secrets_found.append({
                    "type": "RSA/SSH Private Key",
                    "sample": "Found RSA/SSH Private Key block in firmware binary"
                })

            # Check shadow password hashes
            shadow_matches = re.findall(r"\broot:\$[156]\$[a-zA-Z0-9./]{8,64}\b", text)
            if shadow_matches:
                for match in shadow_matches[:5]:
                    secrets_found.append({
                        "type": "Linux Root Shadow Password Hash",
                        "sample": match
                    })

            # Check AWS / Hardcoded API Keys
            aws_matches = re.findall(r"\bAKIA[0-9A-Z]{16}\b", text)
            if aws_matches:
                for match in set(aws_matches[:5]):
                    secrets_found.append({
                        "type": "AWS Access Key ID",
                        "sample": match
                    })

            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={
                    "file_path": str(file_path),
                    "file_size": file_path.stat().st_size,
                    "bytes_scanned": len(content),
                    "header_matches": header_matches,
                    "has_embedded_filesystems": bool(header_matches),
                    "secrets_found": secrets_found,
                    "has_hardcoded_secrets": bool(secrets_found),
                    "summary": f"Firmware scan completed: {len(header_matches)} file system signatures, {len(secrets_found)} hardcoded secrets"
                },
                status="success"
            )

        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error=f"Firmware scan failed: {str(e)}"
            )


firmware_scanner_module = FirmwareScannerModule
