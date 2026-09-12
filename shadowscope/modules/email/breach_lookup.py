"""
Breach Lookup Module for SHADOWSCOPE
Checks if email addresses appear in known data breaches.
"""

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import aiohttp
from rich.console import Console

from shadowscope.core import cache, proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class BreachLookupConfig(ModuleConfig):
    """Configuration for breach lookup module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    check_haveibeenpwned: bool = True
    check_dehashed: bool = True
    check_hunterio: bool = True
    include_verified_only: bool = False

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "haveibeenpwned": "https://haveibeenpwned.com/api/v3",
                "dehashed": "https://api.dehashed.com",
                "hunterio": "https://api.hunter.io/v2",
            }


class BreachLookupModule(BaseModule):
    """
    Breach Lookup Module
    
    Checks if email addresses appear in known data breaches.
    Queries multiple breach databases (Have I Been Pwned, DeHashed, Hunter.io).
    """

    MODULE_NAME = "breach_lookup"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Email OSINT"
    MODULE_DESCRIPTION = "Check email addresses against known data breach databases"
    MODULE_TARGET_TYPES = [TargetType.EMAIL]

    DEFAULT_CONFIG = BreachLookupConfig

    def __init__(self, config: BreachLookupConfig | None = None):
        super().__init__(config or BreachLookupConfig())
        self.session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        if self.config.use_proxy and proxy.is_available():
            proxy_url = proxy.get_random_proxy()
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                proxy=proxy_url
            )
        else:
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the breach lookup module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            # Validate target
            target_type = self.validate_target(target)
            if not target_type:
                result.status = "error"
                result.error = f"Invalid target: {target}"
                return result

            # Normalize email
            email = target.strip().lower()

            # Check cache
            cache_key = f"breach_lookup:{email}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Lookup breaches
            breach_data = await self.lookup_breaches(email)

            # Store in cache
            cache.set(cache_key, breach_data, ttl=86400)  # 24 hours

            result.status = "success"
            result.data = breach_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def lookup_breaches(self, email: str) -> dict[str, Any]:
        """Lookup email in breach databases"""
        data = {
            "email": email,
            "haveibeenpwned": {},
            "dehashed": {},
            "hunterio": {},
            "breaches": [],
            "pastebin": [],
            "analysis": {}
        }

        # Check multiple sources in parallel
        tasks = []

        if self.config.check_haveibeenpwned:
            tasks.append(self.check_haveibeenpwned(email))

        if self.config.check_dehashed:
            tasks.append(self.check_dehashed(email))

        if self.config.check_hunterio:
            tasks.append(self.check_hunterio(email))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                console.print(f"[yellow]Warning: Breach lookup error: {result}[/yellow]")
                continue
            if result:
                self.merge_breach_data(data, result)

        # Analyze the data
        data["analysis"] = self.analyze_breach_data(data)

        return data

    async def check_haveibeenpwned(self, email: str) -> dict[str, Any] | None:
        """Check Have I Been Pwned API for email breaches"""
        base_url = self.config.api_endpoints["haveibeenpwned"]

        try:
            # Get SHA-1 hash of email for HIBP API
            sha1_email = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
            prefix = sha1_email[:5]
            suffix = sha1_email[5:]

            # Check breaches
            url = f"{base_url}/breachedaccount/{email}"
            headers = {
                "hibp-api-key": "",  # Add API key if configured
                "User-Agent": "SHADOWSCOPE"
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    breaches = await response.json()
                    return {
                        "source": "haveibeenpwned",
                        "breaches": breaches,
                        "count": len(breaches)
                    }
                elif response.status == 404:
                    return {"source": "haveibeenpwned", "count": 0}
                elif response.status == 401:
                    console.print("[yellow]Warning: HIBP requires API key[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: HIBP check failed: {e}[/yellow]")

        return None

    async def check_dehashed(self, email: str) -> dict[str, Any] | None:
        """Check DeHashed API for email breaches"""
        base_url = self.config.api_endpoints["dehashed"]

        try:
            # DeHashed uses basic auth
            # Note: DeHashed requires API key and email
            url = f"{base_url}/search?query={email}"

            headers = {
                "Authorization": "Basic " + "",  # Add base64 encoded credentials
                "Accept": "application/json"
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "dehashed",
                        "results": data.get("entries", []),
                        "count": data.get("total", 0)
                    }
                elif response.status == 401:
                    console.print("[yellow]Warning: DeHashed requires API credentials[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: DeHashed check failed: {e}[/yellow]")

        return None

    async def check_hunterio(self, email: str) -> dict[str, Any] | None:
        """Check Hunter.io API for email information"""
        base_url = self.config.api_endpoints["hunterio"]

        try:
            url = f"{base_url}/email-verifier?email={email}"

            headers = {
                "Authorization": "Bearer " + "",  # Add API key
                "Accept": "application/json"
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "source": "hunterio",
                        "data": data,
                        "is_verified": data.get("data", {}).get("status") == "verified"
                    }
                elif response.status == 401:
                    console.print("[yellow]Warning: Hunter.io requires API key[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Hunter.io check failed: {e}[/yellow]")

        return None

    def merge_breach_data(self, target: dict[str, Any], source: dict[str, Any]) -> None:
        """Merge breach data from a source into the target"""
        source_name = source.get("source")

        if source_name == "haveibeenpwned":
            target["haveibeenpwned"] = source

            # Add breaches to combined list
            for breach in source.get("breaches", []):
                target["breaches"].append({
                    "source": "haveibeenpwned",
                    "name": breach.get("Name"),
                    "title": breach.get("Title"),
                    "domain": breach.get("Domain"),
                    "breach_date": breach.get("BreachDate"),
                    "added_date": breach.get("AddedDate"),
                    "modified_date": breach.get("ModifiedDate"),
                    "pwn_count": breach.get("PwnCount"),
                    "description": breach.get("Description"),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified"),
                    "is_fabricated": breach.get("IsFabricated"),
                    "is_sensitive": breach.get("IsSensitive"),
                    "is_retired": breach.get("IsRetired"),
                    "is_spam_list": breach.get("IsSpamList")
                })

        elif source_name == "dehashed":
            target["dehashed"] = source

            # Add entries to breaches list
            for entry in source.get("results", []):
                target["breaches"].append({
                    "source": "dehashed",
                    "database": entry.get("database_name"),
                    "category": entry.get("category"),
                    "entries": entry.get("entries"),
                    "date_added": entry.get("date_added"),
                    "date_leaked": entry.get("date_leaked")
                })

        elif source_name == "hunterio":
            target["hunterio"] = source

    def analyze_breach_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze breach data"""
        analysis = {
            "email": data["email"],
            "total_breaches": len(data["breaches"]),
            "hibp_breaches": data["haveibeenpwned"].get("count", 0),
            "dehashed_results": data["dehashed"].get("count", 0),
            "is_verified": data["hunterio"].get("is_verified", False),
            "is_pwned": False,
            "risk_level": "low",
            "compromised_data_types": [],
            "recommendations": []
        }

        # Check if email is pwned
        if analysis["total_breaches"] > 0:
            analysis["is_pwned"] = True

        # Determine risk level
        if analysis["total_breaches"] > 10:
            analysis["risk_level"] = "critical"
        elif analysis["total_breaches"] > 5:
            analysis["risk_level"] = "high"
        elif analysis["total_breaches"] > 0:
            analysis["risk_level"] = "medium"

        # Extract compromised data types
        for breach in data["breaches"]:
            data_classes = breach.get("data_classes", [])
            if data_classes:
                for data_class in data_classes:
                    if data_class not in analysis["compromised_data_types"]:
                        analysis["compromised_data_types"].append(data_class)

        # Generate recommendations
        if analysis["is_pwned"]:
            analysis["recommendations"].append(
                f"CRITICAL: Email appears in {analysis['total_breaches']} breach(es)"
            )

        if analysis["is_verified"]:
            analysis["recommendations"].append(
                "Email is verified and deliverable"
            )
        else:
            analysis["recommendations"].append(
                "Email verification status unknown"
            )

        if analysis["compromised_data_types"]:
            analysis["recommendations"].append(
                f"Compromised data types: {', '.join(analysis['compromised_data_types'])}"
            )

        # Check for sensitive data
        sensitive_types = ["passwords", "credit cards", "ssn", "phone", "address"]
        for sensitive_type in sensitive_types:
            if sensitive_type in analysis["compromised_data_types"]:
                analysis["recommendations"].append(
                    f"HIGH RISK: Sensitive data ({sensitive_type}) compromised"
                )

        if not analysis["is_pwned"]:
            analysis["recommendations"].append(
                "No breaches found for this email"
            )

        return analysis

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""
        import re

        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL

        return None


# Module instance
breach_lookup_module = BreachLookupModule
