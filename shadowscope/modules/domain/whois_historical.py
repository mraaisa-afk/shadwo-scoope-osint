"""
WHOIS Historical Lookup Module for SHADOWSCOPE
Retrieves historical WHOIS records for domain intelligence.
"""

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
class WhoisHistoricalConfig(ModuleConfig):
    """Configuration for WHOIS historical lookup module"""
    api_url: str = "https://api.domaintools.com/api/v1/history/"
    api_key: str | None = None
    timeout: float = 30.0
    use_proxy: bool = True
    max_records: int = 100
    include_redacted: bool = True
    parse_contacts: bool = True


class WhoisHistoricalModule(BaseModule):
    """
    WHOIS Historical Lookup Module
    
    Retrieves historical WHOIS records to track domain ownership changes,
    detect privacy protection, and uncover redacted information.
    """

    MODULE_NAME = "whois_historical"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Domain Recon"
    MODULE_DESCRIPTION = "Historical WHOIS record analysis"
    MODULE_TARGET_TYPES = [TargetType.DOMAIN]

    DEFAULT_CONFIG = WhoisHistoricalConfig

    def __init__(self, config: WhoisHistoricalConfig | None = None):
        super().__init__(config or WhoisHistoricalConfig())
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
        """Execute the WHOIS historical lookup module"""
        result = ModuleResult(
            module=self.MODULE_NAME,
            target=target,
            status="started",
            start_time=datetime.utcnow()
        )

        try:
            # Validate target
            if not self.validate_target(target):
                result.status = "error"
                result.error = f"Invalid target: {target}. Expected domain."
                return result

            # Check cache
            cache_key = f"whois_historical:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Get historical WHOIS data
            whois_data = await self.get_historical_whois(target)

            # Parse and analyze
            parsed_data = self.parse_whois_data(whois_data, target)

            # Store in cache
            cache.set(cache_key, parsed_data, ttl=86400)  # 24 hours

            result.status = "success"
            result.data = parsed_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def get_historical_whois(self, domain: str) -> dict[str, Any]:
        """Get historical WHOIS records from various sources"""
        data = {
            "domain": domain,
            "records": [],
            "sources": []
        }

        # Try DomainTools API
        if self.config.api_key:
            dt_data = await self.query_domaintools(domain)
            if dt_data:
                data["records"].extend(dt_data.get("records", []))
                data["sources"].append("domaintools")

        # Try free sources
        free_data = await self.query_free_sources(domain)
        if free_data:
            data["records"].extend(free_data.get("records", []))
            data["sources"].extend(free_data.get("sources", []))

        # Sort by date
        data["records"].sort(key=lambda x: x.get("date", ""), reverse=True)

        return data

    async def query_domaintools(self, domain: str) -> dict[str, Any] | None:
        """Query DomainTools API for historical WHOIS"""
        if not self.config.api_key:
            return None

        url = f"{self.config.api_url}whois/{domain}"

        try:
            headers = {
                "Accept": "application/json",
                "X-Api-Key": self.config.api_key
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            console.print(f"[yellow]Warning: DomainTools query failed: {e}[/yellow]")

        return None

    async def query_free_sources(self, domain: str) -> dict[str, Any]:
        """Query free historical WHOIS sources"""
        data = {
            "records": [],
            "sources": []
        }

        # Try ViewDNS.info
        viewdns_data = await self.query_viewdns(domain)
        if viewdns_data:
            data["records"].extend(viewdns_data)
            data["sources"].append("viewdns")

        # Try SecurityTrails
        st_data = await self.query_securitytrails(domain)
        if st_data:
            data["records"].extend(st_data)
            data["sources"].append("securitytrails")

        return data

    async def query_viewdns(self, domain: str) -> list[dict[str, Any]]:
        """Query ViewDNS.info for historical WHOIS"""
        url = f"https://api.viewdns.info/whoishistory/?domain={domain}&apikey=free"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    json_data = await response.json()
                    if json_data.get("query", {}).get("status") == "OK":
                        records = []
                        for item in json_data.get("query", {}).get("data", []):
                            records.append({
                                "date": item.get("date"),
                                "registrar": item.get("registrar"),
                                "owner": item.get("owner"),
                                "raw": item
                            })
                        return records
        except Exception as e:
            console.print(f"[yellow]Warning: ViewDNS query failed: {e}[/yellow]")

        return []

    async def query_securitytrails(self, domain: str) -> list[dict[str, Any]]:
        """Query SecurityTrails for historical data"""
        url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"

        try:
            headers = {
                "Accept": "application/json",
                "APIKEY": self.config.api_key or "free"
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    json_data = await response.json()
                    records = []

                    # Parse current WHOIS
                    current = json_data.get("current", {})
                    if current:
                        records.append({
                            "date": current.get("creation_date"),
                            "registrar": current.get("registrar"),
                            "owner": current.get("registrant", {}).get("organization"),
                            "raw": current
                        })

                    # Parse history if available
                    history = json_data.get("history", [])
                    for item in history:
                        records.append({
                            "date": item.get("date"),
                            "registrar": item.get("registrar"),
                            "owner": item.get("registrant", {}).get("organization"),
                            "raw": item
                        })

                    return records
        except Exception as e:
            console.print(f"[yellow]Warning: SecurityTrails query failed: {e}[/yellow]")

        return []

    def parse_whois_data(self, data: dict[str, Any], domain: str) -> dict[str, Any]:
        """Parse and analyze WHOIS data"""
        parsed = {
            "domain": domain,
            "current": {},
            "history": [],
            "analysis": {
                "ownership_changes": 0,
                "registrar_changes": 0,
                "privacy_protected": False,
                "redacted_count": 0,
                "earliest_record": None,
                "latest_record": None
            }
        }

        if not data.get("records"):
            return parsed

        # Get current record (most recent)
        parsed["current"] = data["records"][0]

        # Process history
        previous_owner = None
        previous_registrar = None

        for record in data["records"]:
            history_item = {
                "date": record.get("date"),
                "registrar": record.get("registrar"),
                "owner": record.get("owner"),
                "raw": record.get("raw")
            }

            # Analyze changes
            current_owner = record.get("owner")
            current_registrar = record.get("registrar")

            if previous_owner and current_owner and previous_owner != current_owner:
                parsed["analysis"]["ownership_changes"] += 1

            if previous_registrar and current_registrar and previous_registrar != current_registrar:
                parsed["analysis"]["registrar_changes"] += 1

            # Check for privacy protection
            raw = record.get("raw", {})
            if self.is_privacy_protected(raw):
                parsed["analysis"]["privacy_protected"] = True

            # Count redacted fields
            redacted = self.count_redacted_fields(raw)
            parsed["analysis"]["redacted_count"] += redacted

            previous_owner = current_owner
            previous_registrar = current_registrar

            parsed["history"].append(history_item)

        # Set earliest and latest
        if data["records"]:
            parsed["analysis"]["earliest_record"] = data["records"][-1].get("date")
            parsed["analysis"]["latest_record"] = data["records"][0].get("date")

        # Limit history to max_records
        parsed["history"] = parsed["history"][:self.config.max_records]

        return parsed

    def is_privacy_protected(self, whois_data: dict[str, Any]) -> bool:
        """Check if WHOIS record has privacy protection"""
        privacy_indicators = [
            "privacy", "protect", "domains by proxy", "whois privacy",
            "privacy service", "registration private", "private registration"
        ]

        for key, value in whois_data.items():
            if isinstance(value, str):
                value_lower = value.lower()
                for indicator in privacy_indicators:
                    if indicator in value_lower:
                        return True

        return False

    def count_redacted_fields(self, whois_data: dict[str, Any]) -> int:
        """Count redacted fields in WHOIS data"""
        redacted_values = ["redacted", "[redacted]", "***", "hidden", "private"]
        count = 0

        def check_value(value):
            nonlocal count
            if isinstance(value, str):
                for redacted in redacted_values:
                    if redacted in value.lower():
                        count += 1
                        break
            elif isinstance(value, dict):
                for v in value.values():
                    check_value(v)
            elif isinstance(value, list):
                for item in value:
                    check_value(item)

        check_value(whois_data)
        return count

    def validate_target(self, target: str) -> bool:
        """Validate that the target is a domain"""
        import re
        pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$"
        return bool(re.match(pattern, target))


# Module instance
whois_historical_module = WhoisHistoricalModule
