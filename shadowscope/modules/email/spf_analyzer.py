"""
SPF Analyzer Module for SHADOWSCOPE
Analyzes SPF, DKIM, and DMARC records for email domains.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import aiohttp
import dns.resolver
from rich.console import Console

from shadowscope.core import cache, proxy
from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

console = Console()


@dataclass
class SPFAnalyzerConfig(ModuleConfig):
    """Configuration for SPF analyzer module"""
    dns_servers: list[str] = field(default_factory=lambda: [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"
    ])
    timeout: float = 10.0
    use_proxy: bool = False
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True
    check_mx: bool = True
    check_dnssec: bool = True


class SPFAnalyzerModule(BaseModule):
    """
    SPF Analyzer Module
    
    Analyzes SPF, DKIM, and DMARC records for email domains.
    Checks for misconfigurations and security vulnerabilities.
    """

    MODULE_NAME = "spf_analyzer"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Email OSINT"
    MODULE_DESCRIPTION = "SPF, DKIM, and DMARC record analysis for email domains"
    MODULE_TARGET_TYPES = [TargetType.EMAIL, TargetType.DOMAIN]

    DEFAULT_CONFIG = SPFAnalyzerConfig

    def __init__(self, config: SPFAnalyzerConfig | None = None):
        super().__init__(config or SPFAnalyzerConfig())
        self.session: aiohttp.ClientSession | None = None
        self.dns_resolver: dns.resolver.Resolver | None = None

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

        # Initialize DNS resolver
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.nameservers = self.config.dns_servers
        self.dns_resolver.timeout = self.config.timeout
        self.dns_resolver.lifetime = self.config.timeout

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the SPF analyzer module"""
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

            # Extract domain from email if needed
            domain = target
            if target_type == TargetType.EMAIL:
                domain = target.split("@")[-1]

            # Check cache
            cache_key = f"spf_analyzer:{domain}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Analyze records
            analysis_data = await self.analyze_records(domain)

            # Store in cache
            cache.set(cache_key, analysis_data, ttl=86400)  # 24 hours

            result.status = "success"
            result.data = analysis_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def analyze_records(self, domain: str) -> dict[str, Any]:
        """Analyze SPF, DKIM, and DMARC records for a domain"""
        data = {
            "domain": domain,
            "spf": {},
            "dkim": {},
            "dmarc": {},
            "mx": {},
            "dnssec": {},
            "analysis": {}
        }

        # Check SPF record
        if self.config.check_spf:
            data["spf"] = await self.check_spf_record(domain)

        # Check DKIM record
        if self.config.check_dkim:
            data["dkim"] = await self.check_dkim_record(domain)

        # Check DMARC record
        if self.config.check_dmarc:
            data["dmarc"] = await self.check_dmarc_record(domain)

        # Check MX records
        if self.config.check_mx:
            data["mx"] = await self.check_mx_records(domain)

        # Check DNSSEC
        if self.config.check_dnssec:
            data["dnssec"] = await self.check_dnssec(domain)

        # Analyze the data
        data["analysis"] = self.analyze_dns_records(data)

        return data

    async def check_spf_record(self, domain: str) -> dict[str, Any]:
        """Check SPF record for a domain"""
        result = {
            "exists": False,
            "record": None,
            "valid": False,
            "mechanisms": [],
            "includes": [],
            "redirects": [],
            "errors": [],
            "warnings": []
        }

        try:
            # Query TXT record for SPF
            answers = self.dns_resolver.resolve(domain, "TXT")

            for rdata in answers:
                record = rdata.to_text().strip('"')

                # Check if this is an SPF record
                if record.startswith("v=spf1"):
                    result["exists"] = True
                    result["record"] = record

                    # Parse SPF mechanisms
                    mechanisms = record.split()

                    for mechanism in mechanisms:
                        if mechanism.startswith("v=spf1"):
                            continue
                        elif mechanism.startswith("include:"):
                            result["includes"].append(mechanism[8:])
                        elif mechanism.startswith("redirect="):
                            result["redirects"].append(mechanism[9:])
                        elif mechanism in ["a", "mx", "ip4", "ip6", "ptr", "exists"]:
                            result["mechanisms"].append(mechanism)
                        elif mechanism.startswith("a:") or mechanism.startswith("mx:"):
                            result["mechanisms"].append(mechanism)
                        elif mechanism.startswith("ip4:") or mechanism.startswith("ip6:"):
                            result["mechanisms"].append(mechanism)
                        elif mechanism == "all":
                            result["mechanisms"].append("all")

                    # Validate SPF record
                    result["valid"] = self.validate_spf_record(record)

                    break

            # Check for common issues
            if result["exists"]:
                if not result["valid"]:
                    result["errors"].append("SPF record is invalid")

                # Check for too many DNS lookups
                lookup_count = len(result["includes"]) + len(result["redirects"])
                if lookup_count > 10:
                    result["errors"].append(
                        f"Too many DNS lookups ({lookup_count}) - exceeds 10 limit"
                    )

                # Check if all mechanism is at the end
                if "all" in result["mechanisms"]:
                    all_index = mechanisms.index("all") if "all" in mechanisms else -1
                    if all_index != len(mechanisms) - 1:
                        result["warnings"].append(
                            "ALL mechanism should be at the end of the SPF record"
                        )
            else:
                result["warnings"].append("No SPF record found")

        except Exception as e:
            result["errors"].append(f"Failed to check SPF: {e}")

        return result

    async def check_dkim_record(self, domain: str) -> dict[str, Any]:
        """Check DKIM record for a domain"""
        result = {
            "exists": False,
            "record": None,
            "valid": False,
            "selectors": [],
            "public_keys": [],
            "errors": [],
            "warnings": []
        }

        # Common DKIM selectors
        selectors = ["default", "google", "google._domainkey", "selector1", "selector2"]

        try:
            for selector in selectors:
                dkim_query = f"{selector}._domainkey.{domain}"

                try:
                    answers = self.dns_resolver.resolve(dkim_query, "TXT")

                    for rdata in answers:
                        record = rdata.to_text().strip('"')
                        result["exists"] = True
                        result["selectors"].append(selector)
                        result["public_keys"].append(record)

                        # Validate DKIM record
                        if self.validate_dkim_record(record):
                            result["valid"] = True

                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue

            if not result["exists"]:
                result["warnings"].append("No DKIM records found")

        except Exception as e:
            result["errors"].append(f"Failed to check DKIM: {e}")

        return result

    async def check_dmarc_record(self, domain: str) -> dict[str, Any]:
        """Check DMARC record for a domain"""
        result = {
            "exists": False,
            "record": None,
            "valid": False,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": [],
            "ruf": [],
            "errors": [],
            "warnings": []
        }

        try:
            # Query TXT record for DMARC
            dmarc_query = f"_dmarc.{domain}"
            answers = self.dns_resolver.resolve(dmarc_query, "TXT")

            for rdata in answers:
                record = rdata.to_text().strip('"')
                result["exists"] = True
                result["record"] = record

                # Parse DMARC record
                parts = record.split(";")

                for part in parts:
                    part = part.strip()
                    if part.startswith("v=DMARC1"):
                        continue
                    elif part.startswith("p="):
                        result["policy"] = part[2:]
                    elif part.startswith("sp="):
                        result["subdomain_policy"] = part[3:]
                    elif part.startswith("pct="):
                        result["pct"] = part[4:]
                    elif part.startswith("rua="):
                        result["rua"].append(part[4:])
                    elif part.startswith("ruf="):
                        result["ruf"].append(part[4:])

                # Validate DMARC record
                result["valid"] = self.validate_dmarc_record(record)

                break

            if not result["exists"]:
                result["warnings"].append("No DMARC record found")
            else:
                # Check policy
                if result["policy"] == "none":
                    result["warnings"].append(
                        "DMARC policy is 'none' - not protecting against spoofing"
                    )
                elif result["policy"] == "quarantine":
                    result["warnings"].append(
                        "DMARC policy is 'quarantine' - consider 'reject' for better protection"
                    )

                # Check if Rua is configured
                if not result["rua"]:
                    result["warnings"].append(
                        "No Rua (reporting) address configured"
                    )

        except Exception as e:
            result["errors"].append(f"Failed to check DMARC: {e}")

        return result

    async def check_mx_records(self, domain: str) -> dict[str, Any]:
        """Check MX records for a domain"""
        result = {
            "exists": False,
            "records": [],
            "preferences": [],
            "servers": [],
            "errors": [],
            "warnings": []
        }

        try:
            answers = self.dns_resolver.resolve(domain, "MX")

            for rdata in answers:
                result["exists"] = True
                result["records"].append(rdata.to_text())
                result["preferences"].append(rdata.preference)
                result["servers"].append(str(rdata.exchange))

            if not result["exists"]:
                result["warnings"].append("No MX records found")

        except Exception as e:
            result["errors"].append(f"Failed to check MX: {e}")

        return result

    async def check_dnssec(self, domain: str) -> dict[str, Any]:
        """Check DNSSEC for a domain"""
        result = {
            "enabled": False,
            "valid": False,
            "ds_record": None,
            "errors": [],
            "warnings": []
        }

        try:
            # Query DS record
            ds_query = f"_ds.{domain}"
            answers = self.dns_resolver.resolve(ds_query, "DS")

            for rdata in answers:
                result["enabled"] = True
                result["ds_record"] = rdata.to_text()
                result["valid"] = True
                break

            if not result["enabled"]:
                result["warnings"].append("DNSSEC not enabled")

        except Exception as e:
            result["errors"].append(f"Failed to check DNSSEC: {e}")

        return result

    def validate_spf_record(self, record: str) -> bool:
        """Validate SPF record syntax"""
        # Basic SPF validation
        if not record.startswith("v=spf1"):
            return False

        # Check for valid mechanisms
        valid_mechanisms = ["a", "mx", "ip4", "ip6", "ptr", "exists", "include", "redirect", "all"]

        parts = record.split()
        for part in parts[1:]:  # Skip v=spf1
            if part in valid_mechanisms:
                continue
            elif part.startswith("a:") or part.startswith("mx:"):
                continue
            elif part.startswith("ip4:") or part.startswith("ip6:"):
                continue
            elif part.startswith("include:"):
                continue
            elif part.startswith("redirect="):
                continue
            elif part.startswith("-") or part.startswith("+") or part.startswith("~"):
                continue
            else:
                return False

        return True

    def validate_dkim_record(self, record: str) -> bool:
        """Validate DKIM record"""
        # Basic DKIM validation
        if "v=DKIM1" not in record:
            return False

        if "p=" not in record:
            return False

        return True

    def validate_dmarc_record(self, record: str) -> bool:
        """Validate DMARC record"""
        if not record.startswith("v=DMARC1"):
            return False

        # Must have p= policy
        if "p=" not in record:
            return False

        return True

    def analyze_dns_records(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze DNS records"""
        analysis = {
            "domain": data["domain"],
            "has_spf": data["spf"].get("exists", False),
            "spf_valid": data["spf"].get("valid", False),
            "has_dkim": data["dkim"].get("exists", False),
            "dkim_valid": data["dkim"].get("valid", False),
            "has_dmarc": data["dmarc"].get("exists", False),
            "dmarc_valid": data["dmarc"].get("valid", False),
            "dmarc_policy": data["dmarc"].get("policy"),
            "has_mx": data["mx"].get("exists", False),
            "mx_count": len(data["mx"].get("records", [])),
            "dnssec_enabled": data["dnssec"].get("enabled", False),
            "is_secure": False,
            "vulnerabilities": [],
            "recommendations": []
        }

        # Determine overall security
        if analysis["has_spf"] and analysis["spf_valid"] and \
           analysis["has_dkim"] and analysis["dkim_valid"] and \
           analysis["has_dmarc"] and analysis["dmarc_valid"]:
            analysis["is_secure"] = True

        # Check for vulnerabilities
        if not analysis["has_spf"]:
            analysis["vulnerabilities"].append(
                "No SPF record - vulnerable to email spoofing"
            )
        elif not analysis["spf_valid"]:
            analysis["vulnerabilities"].append(
                "Invalid SPF record - may not provide protection"
            )

        if not analysis["has_dkim"]:
            analysis["vulnerabilities"].append(
                "No DKIM record - emails cannot be signed"
            )
        elif not analysis["dkim_valid"]:
            analysis["vulnerabilities"].append(
                "Invalid DKIM record - email signing may fail"
            )

        if not analysis["has_dmarc"]:
            analysis["vulnerabilities"].append(
                "No DMARC record - no policy for handling failed SPF/DKIM"
            )
        elif analysis["dmarc_policy"] == "none":
            analysis["vulnerabilities"].append(
                "DMARC policy is 'none' - not protecting against spoofing"
            )

        if not analysis["has_mx"]:
            analysis["vulnerabilities"].append(
                "No MX records - domain may not receive email"
            )

        if not analysis["dnssec_enabled"]:
            analysis["vulnerabilities"].append(
                "DNSSEC not enabled - vulnerable to DNS spoofing"
            )

        # Generate recommendations
        if analysis["is_secure"]:
            analysis["recommendations"].append(
                "Domain has proper email security configuration"
            )
        else:
            analysis["recommendations"].append(
                "Improve email security configuration"
            )

        if not analysis["has_spf"]:
            analysis["recommendations"].append(
                "Add SPF record to prevent email spoofing"
            )

        if not analysis["has_dkim"]:
            analysis["recommendations"].append(
                "Add DKIM record to enable email signing"
            )

        if not analysis["has_dmarc"]:
            analysis["recommendations"].append(
                "Add DMARC record with 'reject' or 'quarantine' policy"
            )
        elif analysis["dmarc_policy"] == "none":
            analysis["recommendations"].append(
                "Change DMARC policy from 'none' to 'quarantine' or 'reject'"
            )

        if not analysis["dnssec_enabled"]:
            analysis["recommendations"].append(
                "Enable DNSSEC for DNS security"
            )

        return analysis

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""
        import re

        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL

        # Check if it's a domain
        domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        if re.match(domain_pattern, target):
            return TargetType.DOMAIN

        return None


# Module instance
spf_analyzer_module = SPFAnalyzerModule
