"""
Alias Hunter Module for SHADOWSCOPE
Finds email aliases and variations for a given email address.
"""

import re
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
class AliasHunterConfig(ModuleConfig):
    """Configuration for alias hunter module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    generate_common_patterns: bool = True
    generate_typos: bool = True
    check_deliverability: bool = True
    check_social: bool = True

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "hunterio": "https://api.hunter.io/v2",
                "clearbit": "https://api.clearbit.com",
            }


class AliasHunterModule(BaseModule):
    """
    Alias Hunter Module
    
    Finds email aliases and variations for a given email address.
    Generates common patterns, typos, and checks for existing aliases.
    """

    MODULE_NAME = "alias_hunter"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Email OSINT"
    MODULE_DESCRIPTION = "Email alias generation and discovery"
    MODULE_TARGET_TYPES = [TargetType.EMAIL]

    DEFAULT_CONFIG = AliasHunterConfig

    def __init__(self, config: AliasHunterConfig | None = None):
        super().__init__(config or AliasHunterConfig())
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
        """Execute the alias hunter module"""
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
            cache_key = f"alias_hunter:{email}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Find aliases
            alias_data = await self.find_aliases(email)

            # Store in cache
            cache.set(cache_key, alias_data, ttl=86400)  # 24 hours

            result.status = "success"
            result.data = alias_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def find_aliases(self, email: str) -> dict[str, Any]:
        """Find aliases for an email address"""
        data = {
            "email": email,
            "domain": email.split("@")[-1],
            "local_part": email.split("@")[0],
            "aliases": {
                "common_patterns": [],
                "typos": [],
                "discovered": [],
                "social": [],
            },
            "analysis": {}
        }

        # Generate common patterns
        if self.config.generate_common_patterns:
            data["aliases"]["common_patterns"] = self.generate_common_patterns(
                data["local_part"], data["domain"]
            )

        # Generate typos
        if self.config.generate_typos:
            data["aliases"]["typos"] = self.generate_typos(
                data["local_part"], data["domain"]
            )

        # Check deliverability
        if self.config.check_deliverability:
            data["aliases"]["discovered"] = await self.check_deliverability(
                data["aliases"]["common_patterns"] + data["aliases"]["typos"]
            )

        # Check social media
        if self.config.check_social:
            data["aliases"]["social"] = await self.check_social(
                data["local_part"], data["domain"]
            )

        # Analyze the data
        data["analysis"] = self.analyze_alias_data(data)

        return data

    def generate_common_patterns(self, local_part: str, domain: str) -> list[str]:
        """Generate common email patterns"""
        patterns = []

        # Common separators
        separators = [".", "_", "-", ""]

        # Split local part
        parts = re.split(r"[._-]", local_part)

        # Generate permutations
        if len(parts) > 1:
            # First initial + last name
            if len(parts) >= 2:
                first_initial = parts[0][0] if parts[0] else ""
                last_name = parts[-1]
                if first_initial and last_name:
                    patterns.append(f"{first_initial}.{last_name}@{domain}")
                    patterns.append(f"{first_initial}_{last_name}@{domain}")
                    patterns.append(f"{first_initial}-{last_name}@{domain}")
                    patterns.append(f"{first_initial}{last_name}@{domain}")

            # First name + last initial
            if len(parts) >= 2:
                first_name = parts[0]
                last_initial = parts[-1][0] if parts[-1] else ""
                if first_name and last_initial:
                    patterns.append(f"{first_name}.{last_initial}@{domain}")
                    patterns.append(f"{first_name}_{last_initial}@{domain}")
                    patterns.append(f"{first_name}-{last_initial}@{domain}")
                    patterns.append(f"{first_name}{last_initial}@{domain}")

            # First + last
            if len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                if first and last:
                    patterns.append(f"{first}.{last}@{domain}")
                    patterns.append(f"{first}_{last}@{domain}")
                    patterns.append(f"{first}-{last}@{domain}")
                    patterns.append(f"{first}{last}@{domain}")
                    patterns.append(f"{last}.{first}@{domain}")
                    patterns.append(f"{last}_{first}@{domain}")
                    patterns.append(f"{last}-{first}@{domain}")
                    patterns.append(f"{last}{first}@{domain}")

        # Common prefixes
        prefixes = ["admin", "support", "info", "contact", "hello", "webmaster"]
        for prefix in prefixes:
            patterns.append(f"{prefix}@{domain}")

        # Common suffixes
        suffixes = ["admin", "user", "test", "backup", "old", "new"]
        for suffix in suffixes:
            patterns.append(f"{local_part}+{suffix}@{domain}")
            patterns.append(f"{local_part}.{suffix}@{domain}")
            patterns.append(f"{local_part}_{suffix}@{domain}")

        # Plus addressing
        patterns.append(f"{local_part}+@{domain}")
        patterns.append(f"{local_part}+test@{domain}")
        patterns.append(f"{local_part}+backup@{domain}")

        # Remove existing duplicates and original
        patterns = list(set(patterns))
        patterns = [p for p in patterns if p.lower() != email.lower()]

        return patterns

    def generate_typos(self, local_part: str, domain: str) -> list[str]:
        """Generate common typos for an email"""
        typos = []

        # Common typo patterns
        # 1. Missing dot
        if "." in local_part:
            typo = local_part.replace(".", "")
            typos.append(f"{typo}@{domain}")

        # 2. Extra dot
        if local_part and not local_part.endswith("."):
            typo = local_part + "."
            typos.append(f"{typo}@{domain}")

        # 3. Missing underscore
        if "_" in local_part:
            typo = local_part.replace("_", "")
            typos.append(f"{typo}@{domain}")

        # 4. Extra underscore
        if local_part and not local_part.endswith("_"):
            typo = local_part + "_"
            typos.append(f"{typo}@{domain}")

        # 5. Common character substitutions
        substitutions = {
            "a": ["4", "@"],
            "e": ["3", "&"],
            "i": ["1", "!"],
            "o": ["0"],
            "s": ["5", "$"],
            "t": ["7"],
            "g": ["9"],
            "b": ["8"],
        }

        for i, char in enumerate(local_part):
            if char.lower() in substitutions:
                for sub in substitutions[char.lower()]:
                    typo = local_part[:i] + sub + local_part[i+1:]
                    typos.append(f"{typo}@{domain}")

        # 6. Transpositions
        for i in range(len(local_part) - 1):
            if local_part[i] != local_part[i+1]:
                typo = local_part[:i] + local_part[i+1] + local_part[i] + local_part[i+2:]
                typos.append(f"{typo}@{domain}")

        # 7. Domain typos
        domain_parts = domain.split(".")
        if len(domain_parts) >= 2:
            # Missing dot in domain
            typo_domain = domain.replace(".", "")
            typos.append(f"{local_part}@{typo_domain}")

            # Common domain typos
            common_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
            for common_domain in common_domains:
                if domain != common_domain:
                    typos.append(f"{local_part}@{common_domain}")

        # Remove duplicates and original
        typos = list(set(typos))
        typos = [t for t in typos if t.lower() != email.lower()]

        return typos

    async def check_deliverability(self, emails: list[str]) -> list[dict[str, Any]]:
        """Check if generated emails are deliverable"""
        discovered = []

        # Use Hunter.io or similar service to check deliverability
        # For now, we'll just return a placeholder
        # In a real implementation, this would call an API

        for email in emails:
            # Simulate API check
            discovered.append({
                "email": email,
                "is_deliverable": None,  # Would be True/False from API
                "source": "placeholder",
                "confidence": None
            })

        return discovered

    async def check_social(self, local_part: str, domain: str) -> list[dict[str, Any]]:
        """Check social media for email aliases"""
        social_aliases = []

        # Common social media username patterns
        # Extract username from email
        username = local_part.split("+")[0]  # Remove plus addressing
        username = username.split("@")[0]  # Remove domain if present

        # Generate common social media email patterns
        social_domains = [
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
            "protonmail.com", "icloud.com", "aol.com"
        ]

        for social_domain in social_domains:
            if social_domain != domain:
                social_aliases.append({
                    "email": f"{username}@{social_domain}",
                    "platform": social_domain,
                    "type": "social_email"
                })

        # Check for common social media username variations
        variations = [
            username,
            f"{username}_official",
            f"{username}_real",
            f"{username}_1",
            f"{username}1",
            f"official_{username}",
            f"real_{username}",
        ]

        for variation in variations:
            social_aliases.append({
                "username": variation,
                "type": "social_username"
            })

        return social_aliases

    def analyze_alias_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze alias data"""
        analysis = {
            "email": data["email"],
            "domain": data["domain"],
            "local_part": data["local_part"],
            "common_patterns_count": len(data["aliases"]["common_patterns"]),
            "typos_count": len(data["aliases"]["typos"]),
            "discovered_count": len(data["aliases"]["discovered"]),
            "social_count": len(data["aliases"]["social"]),
            "total_aliases": len(data["aliases"]["common_patterns"]) +
                           len(data["aliases"]["typos"]) +
                           len(data["aliases"]["social"]),
            "deliverable_count": len([
                d for d in data["aliases"]["discovered"]
                if d.get("is_deliverable")
            ]),
            "recommendations": []
        }

        # Generate recommendations
        if analysis["deliverable_count"] > 0:
            analysis["recommendations"].append(
                f"Found {analysis['deliverable_count']} deliverable aliases"
            )

        if analysis["common_patterns_count"] > 0:
            analysis["recommendations"].append(
                f"Generated {analysis['common_patterns_count']} common pattern aliases"
            )

        if analysis["typos_count"] > 0:
            analysis["recommendations"].append(
                f"Generated {analysis['typos_count']} typo variations"
            )

        if analysis["social_count"] > 0:
            analysis["recommendations"].append(
                f"Found {analysis['social_count']} potential social media aliases"
            )

        if analysis["total_aliases"] == 0:
            analysis["recommendations"].append(
                "No aliases generated - check email format"
            )

        # Check for high confidence discovered aliases
        high_confidence = [
            d for d in data["aliases"]["discovered"]
            if d.get("confidence") and d["confidence"] > 0.8
        ]

        if high_confidence:
            analysis["recommendations"].append(
                f"HIGH CONFIDENCE: {len(high_confidence)} aliases with high confidence"
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
alias_hunter_module = AliasHunterModule
