"""
Disposable Check Module for SHADOWSCOPE
Checks if email addresses are from disposable/temporary email services.
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
class DisposableCheckConfig(ModuleConfig):
    """Configuration for disposable check module"""
    api_endpoints: dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    check_known_domains: bool = True
    check_mx_records: bool = True
    check_api: bool = True

    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "mailboxvalidator": "https://api.mailboxvalidator.com/v1",
                "disposable": "https://disposable.email",
                "trumail": "https://api.trumail.io",
            }


class DisposableCheckModule(BaseModule):
    """
    Disposable Check Module
    
    Checks if email addresses are from disposable/temporary email services.
    Uses domain blacklists, MX record checks, and API services.
    """

    MODULE_NAME = "disposable_check"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Email OSINT"
    MODULE_DESCRIPTION = "Disposable and temporary email detection"
    MODULE_TARGET_TYPES = [TargetType.EMAIL]

    DEFAULT_CONFIG = DisposableCheckConfig

    def __init__(self, config: DisposableCheckConfig | None = None):
        super().__init__(config or DisposableCheckConfig())
        self.session: aiohttp.ClientSession | None = None
        self.disposable_domains: list[str] = []

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

        # Load disposable domains list
        self.disposable_domains = await self.load_disposable_domains()

    async def load_disposable_domains(self) -> list[str]:
        """Load list of known disposable domains"""
        # This would typically load from a file or database
        # For now, we'll use a hardcoded list of common disposable domains

        disposable_domains = [
            # Popular disposable services
            "mailinator.com", "mailinator2.com", "mailinator.net",
            "tempmail.com", "temp-mail.org", "10minutemail.com",
            "guerrillamail.com", "guerrillamail.net", "guerrillamailblock.com",
            "throwawaymail.com", "throwawaymail.net",
            "fakeinbox.com", "fakeinbox.net",
            "tempmail.net", "tempmail.pro",
            "10minutemail.net", "10minutemail.co",
            "33mail.com", "33mail.net",
            "jetable.com", "jetable.net",
            "maildrop.cc", "maildrop.cf",
            "mohmal.com", "mohmal.net",
            "yopmail.com", "yopmail.net",
            "trashmail.com", "trashmail.net", "trashmailer.com",
            "mailexpire.com",
            "getnada.com",
            "temp-mail.io",
            "tempinbox.com",
            "tempinbox.co",
            "temp-mail.org",
            "20minutemail.com",
            "15minutemail.com",
            "5minutemail.com",

            # More disposable domains
            "airmail.cc", "binkmail.com", "dispostable.com",
            "dodosit.com", "dudmail.com", "e4ward.com",
            "emailondeck.com", "fakemail.net", "fakemailz.com",
            "faketemp.net", "fastacura.com", "fudgerub.com",
            "gishpuppy.com", "h8s.org", "halba.dk",
            "hidemail.de", "hochsitze.com", "inboxalias.com",
            "instant-mail.de", "iris7.net", "jetable.fr",
            "kasmail.com", "keinhirn.de", "kicklink.com",
            "koszmail.com", "kurzepost.de", "l33r.eu",
            "lazyinbox.com", "lazyinbox.net",
            "lifetimemail.net", "link2mail.net",
            "lolfreak.net", "mailcatch.com", "maildrop.biz",
            "mailfreeonline.com", "mailnesia.com",
            "mailshell.com", "mailz.tr",
            "mbx.cc", "meltmail.com", "messagebeamer.de",
            "mfsx.org", "moburl.com", "my10minutemail.com",
            "myparts.eu", "notmailinator.com",
            "nowmymail.com", "nospam.ze.tc", "nospam4.us",
            "nospamfor.us", "nospamthanks.info",
            "nullbox.info", "odnorazovoe.ru", "oneoffemail.com",
            "onewaymail.com", "pookmail.com", "privymail.de",
            "proxymail.eu", "quickinbox.com", "rcpt.at",
            "recursor.net", "safemail.net", "scatmail.com",
            "selfdestructingmail.com", "sharklasers.com",
            "shiftmail.com", "shitmail.de", "sibmail.com",
            "smailpro.com", "sofort-mail.de", "spam4.me",
            "spambox.us", "spamex.com", "spamfree.eu",
            "spamgourmet.com", "spamhole.com", "spamspot.com",
            "spamthis.co.uk", "spamtrail.com",
            "speed.1s.fr", "teewars.org", "tempalias.com",
            "tempe-mail.com", "tempemail.biz", "tempemail.co",
            "tempemail.com", "tempemail.net", "temporaryemail.net",
            "temporaryinbox.com", "thanksnospam.info",
            "thisisnotmyrealemail.com", "throwawayemail.com",
            "throwawayemailaddress.com", "tilien.com",
            "tmail.com", "tmail.net", "tmailinator.com",
            "trash2009.com", "trash2010.com", "trash2011.com",
            "trashymail.com", "trashymail.net",
            "trbvm.com", "turual.com", "twinmail.de",
            "uggsrock.com", "veryrealemail.com",
            "viditag.com", "webm4il.info", "willselfdestruct.com",
            "wuzup.net", "wuzupmail.net",
            "yapped.net", "yeah.net", "yopmail.fr",
            "yopmail.net", "yourdomain.com",
            "z1p.biz", "zippymail.info", "zoemail.net",
        ]

        return disposable_domains

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute the disposable check module"""
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
            domain = email.split("@")[-1]

            # Check cache
            cache_key = f"disposable_check:{email}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result

            # Initialize
            await self.initialize()

            # Check if disposable
            disposable_data = await self.check_disposable(email, domain)

            # Store in cache
            cache.set(cache_key, disposable_data, ttl=86400)  # 24 hours

            result.status = "success"
            result.data = disposable_data
            result.end_time = datetime.utcnow()

        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()

        return result

    async def check_disposable(self, email: str, domain: str) -> dict[str, Any]:
        """Check if an email is disposable"""
        data = {
            "email": email,
            "domain": domain,
            "is_disposable": False,
            "is_temp": False,
            "is_role": False,
            "is_free": False,
            "methods": {},
            "confidence": 0.0,
            "reasons": [],
            "analysis": {}
        }

        # Check known disposable domains
        if self.config.check_known_domains:
            data["methods"]["known_domains"] = self.check_known_domains(domain)
            if data["methods"]["known_domains"].get("is_disposable"):
                data["is_disposable"] = True
                data["reasons"].append("Domain in known disposable list")
                data["confidence"] += 0.8

        # Check MX records
        if self.config.check_mx_records:
            data["methods"]["mx_records"] = await self.check_mx_records(domain)
            if data["methods"]["mx_records"].get("is_disposable"):
                data["is_disposable"] = True
                data["reasons"].append("MX records indicate disposable service")
                data["confidence"] += 0.6

        # Check API
        if self.config.check_api:
            data["methods"]["api"] = await self.check_api(email)
            if data["methods"]["api"].get("is_disposable"):
                data["is_disposable"] = True
                data["reasons"].append("API check confirms disposable email")
                data["confidence"] += 0.7

        # Check for role accounts
        data["is_role"] = self.check_role_account(email)
        if data["is_role"]:
            data["reasons"].append("Role account detected")

        # Check for free email providers
        data["is_free"] = self.check_free_provider(domain)
        if data["is_free"]:
            data["reasons"].append("Free email provider detected")

        # Cap confidence
        data["confidence"] = min(data["confidence"], 1.0)

        # Determine if temp
        data["is_temp"] = data["is_disposable"]

        # Analyze the data
        data["analysis"] = self.analyze_disposable_data(data)

        return data

    def check_known_domains(self, domain: str) -> dict[str, Any]:
        """Check if domain is in known disposable list"""
        result = {
            "domain": domain,
            "is_disposable": False,
            "is_temp": False,
            "category": None
        }

        # Check domain and subdomains
        domain_parts = domain.split(".")

        # Check full domain
        if domain.lower() in [d.lower() for d in self.disposable_domains]:
            result["is_disposable"] = True
            result["is_temp"] = True
            result["category"] = "known_disposable"
            return result

        # Check parent domains (e.g., tempmail.com for mail.tempmail.com)
        for i in range(len(domain_parts)):
            parent_domain = ".".join(domain_parts[i:])
            if parent_domain.lower() in [d.lower() for d in self.disposable_domains]:
                result["is_disposable"] = True
                result["is_temp"] = True
                result["category"] = "known_disposable_parent"
                return result

        return result

    async def check_mx_records(self, domain: str) -> dict[str, Any]:
        """Check MX records for disposable indicators"""
        result = {
            "domain": domain,
            "is_disposable": False,
            "mx_records": [],
            "has_mx": False,
            "mx_domains": []
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "8.8.4.4"]

            # Query MX records
            answers = resolver.resolve(domain, "MX")

            for rdata in answers:
                result["has_mx"] = True
                result["mx_records"].append(rdata.to_text())
                result["mx_domains"].append(str(rdata.exchange))

            # Check MX domains against known disposable domains
            for mx_domain in result["mx_domains"]:
                if mx_domain.lower() in [d.lower() for d in self.disposable_domains]:
                    result["is_disposable"] = True
                    return result

                # Check parent domains
                mx_parts = mx_domain.split(".")
                for i in range(len(mx_parts)):
                    parent_domain = ".".join(mx_parts[i:])
                    if parent_domain.lower() in [d.lower() for d in self.disposable_domains]:
                        result["is_disposable"] = True
                        return result

            # Check for common disposable MX patterns
            disposable_mx_patterns = [
                "mx1.mailinator.com",
                "mx.tempmail.com",
                "mx.guerrillamail.com",
                "mail.",
                "mx.",
            ]

            for mx_domain in result["mx_domains"]:
                for pattern in disposable_mx_patterns:
                    if pattern in mx_domain.lower():
                        result["is_disposable"] = True
                        return result

        except Exception as e:
            result["error"] = str(e)

        return result

    async def check_api(self, email: str) -> dict[str, Any]:
        """Check using API services"""
        result = {
            "email": email,
            "is_disposable": False,
            "is_temp": False,
            "source": None,
            "confidence": 0.0
        }

        # Try multiple API services
        # Note: These would require API keys in a real implementation

        # 1. MailboxValidator
        try:
            url = f"{self.config.api_endpoints['mailboxvalidator']}/email/verify?email={email}"
            headers = {
                "Authorization": "Bearer " + "",  # API key
                "Accept": "application/json"
            }

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("is_disposable"):
                        result["is_disposable"] = True
                        result["is_temp"] = True
                        result["source"] = "mailboxvalidator"
                        result["confidence"] = data.get("confidence", 0.7)
        except Exception as e:
            console.print(f"[yellow]Warning: MailboxValidator API failed: {e}[/yellow]")

        # 2. Disposable.email
        if not result["is_disposable"]:
            try:
                url = f"{self.config.api_endpoints['disposable']}/api/v1/disposable/{email}"

                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("disposable"):
                            result["is_disposable"] = True
                            result["is_temp"] = True
                            result["source"] = "disposable.email"
                            result["confidence"] = data.get("confidence", 0.8)
            except Exception as e:
                console.print(f"[yellow]Warning: Disposable.email API failed: {e}[/yellow]")

        # 3. TruMail
        if not result["is_disposable"]:
            try:
                url = f"{self.config.api_endpoints['trumail']}/v2/lookups/json?email={email}"
                headers = {
                    "Authorization": "Bearer " + "",  # API key
                    "Accept": "application/json"
                }

                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("deliverable") == "undeliverable" or data.get("disposable"):
                            result["is_disposable"] = True
                            result["is_temp"] = True
                            result["source"] = "trumail"
                            result["confidence"] = data.get("confidence", 0.6)
            except Exception as e:
                console.print(f"[yellow]Warning: TruMail API failed: {e}[/yellow]")

        return result

    def check_role_account(self, email: str) -> bool:
        """Check if email is a role account"""
        local_part = email.split("@")[0].lower()

        role_accounts = [
            "admin", "administrator", "webmaster", "postmaster",
            "support", "info", "contact", "hello", "help",
            "sales", "marketing", "abuse", "noreply",
            "no-reply", "no-reply", "noreply", "bounce",
            "all", "everyone", "team", "staff",
            "jobs", "careers", "recruiting", "hr",
            "press", "media", "pr",
            "feedback", "comments", "suggestions",
        ]

        return local_part in role_accounts

    def check_free_provider(self, domain: str) -> bool:
        """Check if domain is a free email provider"""
        free_providers = [
            "gmail.com", "googlemail.com",
            "yahoo.com", "ymail.com", "rocketmail.com",
            "outlook.com", "hotmail.com", "live.com", "msn.com",
            "icloud.com", "me.com", "mac.com",
            "aol.com", "aim.com",
            "protonmail.com", "protonmail.ch",
            "zoho.com", "yandex.com",
            "mail.com", "hushmail.com",
            "fastmail.com", "gmx.com", "gmx.net",
        ]

        return domain.lower() in [d.lower() for d in free_providers]

    def analyze_disposable_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze disposable check data"""
        analysis = {
            "email": data["email"],
            "domain": data["domain"],
            "is_disposable": data["is_disposable"],
            "is_temp": data["is_temp"],
            "is_role": data["is_role"],
            "is_free": data["is_free"],
            "confidence": data["confidence"],
            "reasons": data["reasons"],
            "risk_level": "low",
            "recommendations": []
        }

        # Determine risk level
        if data["is_disposable"]:
            analysis["risk_level"] = "high"
        elif data["is_temp"]:
            analysis["risk_level"] = "medium"
        elif data["is_role"]:
            analysis["risk_level"] = "medium"
        elif data["is_free"]:
            analysis["risk_level"] = "low"

        # Generate recommendations
        if data["is_disposable"]:
            analysis["recommendations"].append(
                f"DISPOSABLE: Email is from a disposable service ({', '.join(data['reasons'])})"
            )

        if data["is_temp"]:
            analysis["recommendations"].append(
                "TEMPORARY: Email is from a temporary service"
            )

        if data["is_role"]:
            analysis["recommendations"].append(
                "ROLE ACCOUNT: Email is a role account (admin, support, etc.)"
            )

        if data["is_free"]:
            analysis["recommendations"].append(
                "FREE PROVIDER: Email is from a free provider"
            )

        if not data["is_disposable"] and not data["is_temp"] and not data["is_role"]:
            analysis["recommendations"].append(
                "Email appears to be legitimate"
            )

        # Check confidence
        if data["confidence"] > 0.8:
            analysis["recommendations"].append(
                "HIGH CONFIDENCE: Disposable detection is highly confident"
            )
        elif data["confidence"] > 0.5:
            analysis["recommendations"].append(
                "MEDIUM CONFIDENCE: Disposable detection has medium confidence"
            )

        return analysis

    def validate_target(self, target: str) -> TargetType | None:
        """Validate target and return its type"""

        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL

        return None


# Module instance
disposable_check_module = DisposableCheckModule
