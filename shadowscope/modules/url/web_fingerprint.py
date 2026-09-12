"""
Web Fingerprint Module for SHADOWSCOPE
Fingerprints web application tech stacks, CMS frameworks, server headers, and frontend libraries.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from shadowscope.core.modules import BaseModule, ModuleConfig, ModuleResult
from shadowscope.core.targets import TargetType

# Technology signature patterns
TECH_SIGNATURES: list[dict[str, Any]] = [
    {"name": "WordPress", "category": "CMS", "header": "X-Powered-By", "header_pattern": "WordPress", "html_pattern": "wp-content/"},
    {"name": "Drupal", "category": "CMS", "header": "X-Generator", "header_pattern": "Drupal", "html_pattern": "Drupal.settings"},
    {"name": "Joomla", "category": "CMS", "header": "X-Content-Encoded-By", "header_pattern": "Joomla", "html_pattern": "/media/system/js/"},
    {"name": "Next.js", "category": "Frontend Framework", "header": "X-Powered-By", "header_pattern": "Next.js", "html_pattern": "/_next/"},
    {"name": "React", "category": "Frontend Library", "header": "", "header_pattern": "", "html_pattern": "data-reactroot"},
    {"name": "Vue.js", "category": "Frontend Framework", "header": "", "header_pattern": "", "html_pattern": "data-v-"},
    {"name": "Laravel", "category": "PHP Framework", "header": "Set-Cookie", "header_pattern": "laravel_session", "html_pattern": ""},
    {"name": "Django", "category": "Python Framework", "header": "Set-Cookie", "header_pattern": "csrftoken", "html_pattern": ""},
    {"name": "Nginx", "category": "Web Server", "header": "Server", "header_pattern": "nginx", "html_pattern": ""},
    {"name": "Apache", "category": "Web Server", "header": "Server", "header_pattern": "Apache", "html_pattern": ""},
    {"name": "Cloudflare", "category": "CDN / WAF", "header": "Server", "header_pattern": "cloudflare", "html_pattern": ""},
]


@dataclass
class WebFingerprintConfig(ModuleConfig):
    """Configuration for Web Fingerprint module."""
    check_headers: bool = True


class WebFingerprintModule(BaseModule):
    """Module for identifying web servers, CMS frameworks, CDNs, and JavaScript libraries from response headers and HTML body."""

    MODULE_NAME = "web_fingerprint"
    MODULE_VERSION = "1.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "url"
    MODULE_DESCRIPTION = "Fingerprint web tech stacks, CMS engines (WordPress, Drupal, Joomla), web servers, frameworks, and WAFs"
    MODULE_TARGET_TYPES = [TargetType.URL, TargetType.DOMAIN, TargetType.UNKNOWN]
    MODULE_DEPENDENCIES = ["aiohttp"]
    MODULE_TIMEOUT = 300

    def __init__(self, config: WebFingerprintConfig | None = None) -> None:
        super().__init__(config=config or WebFingerprintConfig())
        self.config: WebFingerprintConfig = self.config if isinstance(self.config, WebFingerprintConfig) else WebFingerprintConfig.from_dict(self.config.to_dict() if hasattr(self.config, "to_dict") else {})

    def validate_target(self, target: str) -> bool:
        """Validate target URL or domain string."""
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        return len(cleaned) > 0

    async def execute(self, target: str, options: dict[str, Any] | None = None) -> ModuleResult:
        """Execute tech stack fingerprinting."""
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if not self.validate_target(target):
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={},
                status="failed",
                error="Invalid URL string"
            )

        detected_tech: list[dict[str, str]] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = resp.headers
                    html = await resp.text()

                    for sig in TECH_SIGNATURES:
                        matched = False
                        hdr_name = sig["header"]
                        hdr_pat = sig["header_pattern"]
                        html_pat = sig["html_pattern"]

                        if hdr_name and hdr_name in headers and hdr_pat and hdr_pat.lower() in headers[hdr_name].lower():
                            matched = True
                        elif html_pat and html_pat.lower() in html.lower():
                            matched = True

                        if matched:
                            detected_tech.append({"name": sig["name"], "category": sig["category"]})

                    server_header = headers.get("Server", "Unknown")

                    return ModuleResult(
                        target=target,
                        module=self.MODULE_NAME,
                        data={
                            "url": url,
                            "server_header": server_header,
                            "tech_stack": detected_tech,
                            "tech_count": len(detected_tech),
                            "summary": f"Web Fingerprint for '{url}': Identified {len(detected_tech)} technologies ({', '.join(t['name'] for t in detected_tech) if detected_tech else 'Server: ' + server_header})"
                        },
                        status="success"
                    )
        except Exception as e:
            return ModuleResult(
                target=target,
                module=self.MODULE_NAME,
                data={"url": url},
                status="failed",
                error=f"Web fingerprinting failed: {str(e)}"
            )


web_fingerprint_module = WebFingerprintModule
