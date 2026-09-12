"""
PGP Fingerprint Module for SHADOWSCOPE
Analyzes and verifies PGP fingerprints and keys.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core import proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class PGPFingerprintConfig(ModuleConfig):
    """Configuration for PGP fingerprint module"""
    keyserver_url: str = "https://hkps.pool.sks-keyservers.net"
    timeout: float = 60.0
    verify_signatures: bool = True
    check_revocation: bool = True
    check_expiration: bool = True
    max_key_size: int = 4096

    def __post_init__(self):
        if not self.keyserver_url.startswith('http'):
            self.keyserver_url = f"https://{self.keyserver_url}"


@dataclass
class PGPKeyInfo:
    """Information about a PGP key"""
    fingerprint: str
    key_id: str = ""
    key_type: str = ""
    key_size: int = 0
    creation_date: str | None = None
    expiration_date: str | None = None
    user_ids: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    subkeys: list[dict[str, Any]] = field(default_factory=list)
    is_valid: bool = True
    is_revoked: bool = False
    is_expired: bool = False
    algorithm: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "key_id": self.key_id,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "user_ids": self.user_ids,
            "emails": self.emails,
            "subkeys": self.subkeys,
            "is_valid": self.is_valid,
            "is_revoked": self.is_revoked,
            "is_expired": self.is_expired,
            "algorithm": self.algorithm
        }


@dataclass
class SignatureInfo:
    """Information about a PGP signature"""
    fingerprint: str
    signature: str
    signed_data: str
    creation_date: str | None = None
    is_valid: bool = False
    key_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "signature": self.signature,
            "signed_data": self.signed_data,
            "creation_date": self.creation_date,
            "is_valid": self.is_valid,
            "key_id": self.key_id
        }


class PGPFingerprintModule(BaseModule):
    """
    PGP Fingerprint Module
    
    Analyzes PGP keys and fingerprints, verifies signatures,
    checks key validity, expiration, and revocation status.
    """

    MODULE_NAME = "pgp_fingerprint"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Dark Web"
    MODULE_DESCRIPTION = "PGP fingerprint analysis, key lookup, and signature verification"
    MODULE_TARGET_TYPES = [TargetType.PGP_KEY, TargetType.USERNAME, TargetType.EMAIL]

    DEFAULT_CONFIG = PGPFingerprintConfig

    def __init__(self, config: PGPFingerprintConfig | None = None):
        super().__init__(config or PGPFingerprintConfig())
        self.session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        """Initialize the module"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def cleanup(self) -> None:
        """Clean up resources"""
        if self.session:
            await self.session.close()

    def _normalize_fingerprint(self, fingerprint: str) -> str:
        """Normalize fingerprint format (remove spaces, uppercase)"""
        return fingerprint.replace(" ", "").upper()

    def _validate_fingerprint_format(self, fingerprint: str) -> bool:
        """Validate PGP fingerprint format (40 hex chars for SHA-1, 64 for SHA-256)"""
        fingerprint = self._normalize_fingerprint(fingerprint)
        # SHA-1 fingerprint: 40 hex characters (160 bits)
        # SHA-256 fingerprint: 64 hex characters (256 bits)
        return bool(re.match(r'^[0-9A-F]{40}$', fingerprint)) or bool(re.match(r'^[0-9A-F]{64}$', fingerprint))

    def _validate_key_id(self, key_id: str) -> bool:
        """Validate PGP key ID format (8 or 16 hex chars)"""
        key_id = key_id.replace(" ", "").upper()
        return bool(re.match(r'^[0-9A-F]{8,16}$', key_id))

    async def _fetch_key_from_keyserver(self, fingerprint: str) -> str | None:
        """Fetch PGP key from keyserver using fingerprint"""
        try:
            # HKP (HTTP Keyserver Protocol) lookup
            # Format: /pks/lookup?op=get&search=0xFINGERPRINT
            search_param = fingerprint if fingerprint.startswith("0x") else f"0x{fingerprint}"
            url = f"{self.config.keyserver_url}/pks/lookup?op=get&search={search_param}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    console.print(f"[yellow]Key not found on keyserver: {fingerprint}[/yellow]")
                    return None

        except aiohttp.ClientError as e:
            console.print(f"[red]Error fetching key from keyserver: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            return None

    async def _fetch_key_by_email(self, email: str) -> str | None:
        """Fetch PGP key from keyserver using email"""
        try:
            url = f"{self.config.keyserver_url}/pks/lookup?op=get&search={email}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    console.print(f"[yellow]No key found for email: {email}[/yellow]")
                    return None

        except aiohttp.ClientError as e:
            console.print(f"[red]Error fetching key by email: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            return None

    async def _fetch_key_by_username(self, username: str) -> str | None:
        """Fetch PGP key from keyserver using username"""
        try:
            url = f"{self.config.keyserver_url}/pks/lookup?op=get&search={username}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    console.print(f"[yellow]No key found for username: {username}[/yellow]")
                    return None

        except aiohttp.ClientError as e:
            console.print(f"[red]Error fetching key by username: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            return None

    def _parse_key_block(self, key_block: str) -> PGPKeyInfo | None:
        """Parse PGP key block and extract information"""
        try:
            key_info = PGPKeyInfo(fingerprint="")

            # Extract fingerprint
            fingerprint_match = re.search(r'Fingerprint[=:]\s*([0-9A-F\s]+)', key_block, re.IGNORECASE)
            if fingerprint_match:
                fingerprint = self._normalize_fingerprint(fingerprint_match.group(1))
                key_info.fingerprint = fingerprint

            # Extract key ID
            key_id_match = re.search(r'Key ID[=:]\s*([0-9A-F\s]+)', key_block, re.IGNORECASE)
            if key_id_match:
                key_info.key_id = key_id_match.group(1).replace(" ", "").upper()

            # Extract key type and size
            key_type_match = re.search(r'Key Type[=:]\s*([^\n]+)', key_block, re.IGNORECASE)
            if key_type_match:
                key_type_text = key_type_match.group(1).strip()
                # Parse "RSA (Encrypt or Sign) 4096 bits" format
                size_match = re.search(r'(\d+) bits', key_type_text)
                if size_match:
                    key_info.key_size = int(size_match.group(1))
                type_match = re.search(r'([A-Z]+)', key_type_text)
                if type_match:
                    key_info.key_type = type_match.group(1)

            # Extract algorithm
            algo_match = re.search(r'Algorithm[=:]\s*([^\n]+)', key_block, re.IGNORECASE)
            if algo_match:
                key_info.algorithm = algo_match.group(1).strip()

            # Extract creation date
            creation_match = re.search(r'Created[=:]\s*([0-9\-]+)', key_block, re.IGNORECASE)
            if creation_match:
                key_info.creation_date = creation_match.group(1)

            # Extract expiration date
            expiration_match = re.search(r'Expires[=:]\s*([0-9\-]+)', key_block, re.IGNORECASE)
            if expiration_match:
                key_info.expiration_date = expiration_match.group(1)

            # Extract user IDs and emails
            uid_section = re.search(r'User IDs[=:]\s*([^\n]+)', key_block, re.IGNORECASE)
            if uid_section:
                uids = uid_section.group(1).strip()
                for uid in uids.split(',') if uids else []:
                    uid = uid.strip()
                    key_info.user_ids.append(uid)
                    # Extract email from user ID
                    email_match = re.search(r'<([^>]+)>', uid)
                    if email_match:
                        key_info.emails.append(email_match.group(1))

            # Check if key is revoked
            if 'REVOKED' in key_block.upper():
                key_info.is_revoked = True
                key_info.is_valid = False

            # Check if key is expired
            if key_info.expiration_date:
                from datetime import datetime
                exp_date = datetime.strptime(key_info.expiration_date, '%Y-%m-%d')
                if exp_date < datetime.utcnow():
                    key_info.is_expired = True
                    key_info.is_valid = False

            return key_info if key_info.fingerprint else None

        except Exception as e:
            console.print(f"[red]Error parsing key block: {e}[/red]")
            return None

    async def _verify_signature(self, fingerprint: str, signature: str, data: str) -> bool:
        """Verify PGP signature (placeholder - requires python-gnupg or similar)"""
        # This is a placeholder implementation
        # In production, use python-gnupg library or call gpg binary
        console.print("[yellow]Signature verification requires python-gnupg library[/yellow]")
        return False

    async def _calculate_fingerprint(self, key_data: str) -> str:
        """Calculate fingerprint from key data (SHA-1)"""
        # Extract the key material (between BEGIN and END PGP)
        key_material_match = re.search(r'-----BEGIN PGP (PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----(.*?)-----END PGP', key_data, re.DOTALL)
        if key_material_match:
            key_material = key_material_match.group(2).strip()
            # Calculate SHA-1 hash
            sha1_hash = hashlib.sha1(key_material.encode()).hexdigest()
            return sha1_hash.upper()
        return ""

    async def _lookup_fingerprint(self, target: str) -> PGPKeyInfo | None:
        """Lookup fingerprint information based on target type"""
        # Check if target is a fingerprint
        if self._validate_fingerprint_format(target):
            key_block = await self._fetch_key_from_keyserver(target)
            if key_block:
                return self._parse_key_block(key_block)

        # Check if target is a key ID
        elif self._validate_key_id(target):
            key_block = await self._fetch_key_from_keyserver(target)
            if key_block:
                return self._parse_key_block(key_block)

        # Check if target is an email
        elif '@' in target:
            key_block = await self._fetch_key_by_email(target)
            if key_block:
                return self._parse_key_block(key_block)

        # Otherwise, treat as username
        else:
            key_block = await self._fetch_key_by_username(target)
            if key_block:
                return self._parse_key_block(key_block)

        return None

    async def _analyze_fingerprint(self, fingerprint: str) -> dict[str, Any]:
        """Perform comprehensive analysis on a fingerprint"""
        analysis = {
            "fingerprint": fingerprint,
            "is_valid_format": self._validate_fingerprint_format(fingerprint),
            "key_length": len(fingerprint.replace(" ", "")),
            "key_type": "SHA-1" if len(fingerprint.replace(" ", "")) == 40 else "SHA-256",
            "checksum": hashlib.sha256(fingerprint.encode()).hexdigest()
        }

        # Lookup key information
        key_info = await self._lookup_fingerprint(fingerprint)
        if key_info:
            analysis["key_info"] = key_info.to_dict()

        return analysis

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the PGP fingerprint module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            options = options or {}

            console.print(f"[blue]Analyzing PGP fingerprint: {target}[/blue]")

            # Check if target is a fingerprint
            if self._validate_fingerprint_format(target):
                analysis = await self._analyze_fingerprint(target)
                result.status = "success"
                result.data = analysis
                result.summary = f"Analyzed fingerprint: {analysis.get('key_type', 'Unknown')} format, {analysis.get('key_length', 0)} chars"

            # Check if target is an email
            elif '@' in target:
                console.print(f"[blue]Looking up PGP key for email: {target}[/blue]")
                key_info = await self._lookup_fingerprint(target)
                if key_info:
                    result.status = "success"
                    result.data = {"email": target, "key_info": key_info.to_dict()}
                    result.summary = f"Found PGP key for email: {key_info.fingerprint}"
                else:
                    result.status = "partial"
                    result.error = f"No PGP key found for email: {target}"

            # Otherwise treat as username or key ID
            else:
                console.print(f"[blue]Looking up PGP key for identifier: {target}[/blue]")
                key_info = await self._lookup_fingerprint(target)
                if key_info:
                    result.status = "success"
                    result.data = {"identifier": target, "key_info": key_info.to_dict()}
                    result.summary = f"Found PGP key: {key_info.fingerprint}"
                else:
                    result.status = "partial"
                    result.error = f"No PGP key found for identifier: {target}"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            console.print(f"[red]Error analyzing PGP fingerprint: {e}[/red]")

        result.end_time = datetime.utcnow()
        return result

    async def execute_batch(self, targets: list[str], options: dict[str, Any] | None = None) -> list[ModuleResult]:
        """Execute on multiple targets"""
        results = []
        for target in targets:
            result = await self.execute(target, options)
            results.append(result)
        return results


# Module instance
pgp_fingerprint_module = PGPFingerprintModule()
