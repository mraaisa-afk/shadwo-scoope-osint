"""
Header Forensics Module for SHADOWSCOPE
Analyzes email headers for forensic information.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import re
import hashlib

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class HeaderForensicsConfig(ModuleConfig):
    """Configuration for header forensics module"""
    api_endpoints: Dict[str, str] = None
    timeout: float = 60.0
    use_proxy: bool = True
    max_retries: int = 3
    parse_received: bool = True
    extract_ips: bool = True
    geolocate_ips: bool = True
    check_spam: bool = True
    
    def __post_init__(self):
        if self.api_endpoints is None:
            self.api_endpoints = {
                "ipinfo": "https://ipinfo.io",
                "ipapi": "https://ipapi.co",
                "abuseipdb": "https://api.abuseipdb.com",
            }


class HeaderForensicsModule(BaseModule):
    """
    Header Forensics Module
    
    Analyzes email headers for forensic information.
    Extracts IP addresses, geolocation, routing paths, and spam indicators.
    """
    
    MODULE_NAME = "header_forensics"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "Email OSINT"
    MODULE_DESCRIPTION = "Email header forensic analysis and IP extraction"
    MODULE_TARGET_TYPES = [TargetType.EMAIL]
    
    DEFAULT_CONFIG = HeaderForensicsConfig
    
    def __init__(self, config: Optional[HeaderForensicsConfig] = None):
        super().__init__(config or HeaderForensicsConfig())
        self.session: Optional[aiohttp.ClientSession] = None
    
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
    
    async def execute(self, target: str, options: Optional[Dict[str, Any]] = None) -> ModuleResult:
        """Execute the header forensics module"""
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
            
            # Check if options contain headers
            headers = options.get("headers") if options else None
            if not headers:
                result.status = "error"
                result.error = "No email headers provided"
                return result
            
            # Check cache
            cache_key = f"header_forensics:{hashlib.md5(headers.encode()).hexdigest()}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Analyze headers
            analysis_data = await self.analyze_headers(headers)
            
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
    
    async def analyze_headers(self, headers: str) -> Dict[str, Any]:
        """Analyze email headers"""
        data = {
            "headers": headers,
            "parsed": {},
            "ips": [],
            "servers": [],
            "routing": [],
            "timestamps": [],
            "spam_indicators": [],
            "anomalies": [],
            "analysis": {}
        }
        
        # Parse headers
        parsed_headers = self.parse_headers(headers)
        data["parsed"] = parsed_headers
        
        # Extract IPs
        if self.config.extract_ips:
            data["ips"] = self.extract_ips(parsed_headers)
        
        # Extract servers
        data["servers"] = self.extract_servers(parsed_headers)
        
        # Analyze routing
        if self.config.parse_received:
            data["routing"] = self.analyze_routing(parsed_headers)
        
        # Extract timestamps
        data["timestamps"] = self.extract_timestamps(parsed_headers)
        
        # Check for spam indicators
        if self.config.check_spam:
            data["spam_indicators"] = self.check_spam_indicators(parsed_headers)
        
        # Detect anomalies
        data["anomalies"] = self.detect_anomalies(data)
        
        # Analyze the data
        data["analysis"] = self.analyze_header_data(data)
        
        return data
    
    def parse_headers(self, headers: str) -> Dict[str, Any]:
        """Parse email headers into a structured format"""
        parsed = {}
        
        # Split headers by lines
        lines = headers.split("\n")
        
        current_header = None
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            
            # Check if this is a header line (not a continuation)
            if ":" in line and not line.startswith(" ") and not line.startswith("\t"):
                # New header
                header_name, header_value = line.split(":", 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                
                parsed[header_name] = header_value
                current_header = header_name
            elif line.startswith(" ") or line.startswith("\t"):
                # Continuation of previous header
                if current_header:
                    parsed[current_header] += " " + line.strip()
        
        return parsed
    
    def extract_ips(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IP addresses from headers"""
        ips = []
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        
        # Headers that typically contain IPs
        ip_headers = ["Received", "X-Forwarded-For", "X-Originating-IP", "Client-IP"]
        
        for header_name, header_value in headers.items():
            if any(ip_header in header_name for ip_header in ip_headers):
                # Find all IPs in this header
                matches = re.findall(ip_pattern, header_value)
                
                for ip in matches:
                    # Validate IP
                    if self.validate_ip(ip):
                        ips.append({
                            "ip": ip,
                            "source": header_name,
                            "header": header_value
                        })
        
        return ips
    
    def extract_servers(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract server information from headers"""
        servers = []
        
        # Headers that contain server information
        server_headers = ["Received", "Server", "X-Mailer", "User-Agent"]
        
        for header_name, header_value in headers.items():
            if any(server_header in header_name for server_header in server_headers):
                servers.append({
                    "header": header_name,
                    "value": header_value
                })
        
        return servers
    
    def analyze_routing(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email routing path"""
        routing = []
        
        # Parse Received headers
        received_headers = [
            (k, v) for k, v in headers.items() 
            if "Received" in k
        ]
        
        # Sort by order (first Received is last hop)
        received_headers.reverse()
        
        for header_name, header_value in received_headers:
            # Parse Received header
            routing_info = self.parse_received_header(header_value)
            if routing_info:
                routing.append(routing_info)
        
        return routing
    
    def parse_received_header(self, header: str) -> Optional[Dict[str, Any]]:
        """Parse a Received header"""
        # Typical format: from server1.example.com (server1.example.com [192.168.1.1])
        #                  by server2.example.com (server2.example.com [10.0.0.1])
        
        result = {}
        
        # Extract from
        from_match = re.search(r"from\s+([^\s]+)\s*\(", header, re.IGNORECASE)
        if from_match:
            result["from"] = from_match.group(1)
        
        # Extract from IP
        from_ip_match = re.search(r"from\s+[^\(\s]+\s*\([^\[\]]*\\[([\d.]+)\\]", header, re.IGNORECASE)
        if from_ip_match:
            result["from_ip"] = from_ip_match.group(1)
        
        # Extract by
        by_match = re.search(r"by\s+([^\s]+)", header, re.IGNORECASE)
        if by_match:
            result["by"] = by_match.group(1)
        
        # Extract by IP
        by_ip_match = re.search(r"by\s+[^\s]+\s*\([^\[\]]*\\[([\d.]+)\\]", header, re.IGNORECASE)
        if by_ip_match:
            result["by_ip"] = by_ip_match.group(1)
        
        # Extract timestamp
        timestamp_match = re.search(r"(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)", header)
        if timestamp_match:
            result["timestamp"] = timestamp_match.group(1)
        
        # Extract via
        via_match = re.search(r"via\s+([^\s;]+)", header, re.IGNORECASE)
        if via_match:
            result["via"] = via_match.group(1)
        
        # Extract with
        with_match = re.search(r"with\s+([^\s;]+)", header, re.IGNORECASE)
        if with_match:
            result["with"] = with_match.group(1)
        
        if not result:
            return None
        
        return result
    
    def extract_timestamps(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract timestamps from headers"""
        timestamps = []
        
        # Headers that contain timestamps
        timestamp_headers = ["Date", "Received", "X-Received", "X-Sent"]
        
        for header_name, header_value in headers.items():
            if any(ts_header in header_name for ts_header in timestamp_headers):
                # Find timestamps in header value
                # Common formats: RFC 2822, ISO 8601
                timestamp_patterns = [
                    r"(\w+,\s+\d+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+[+-]\d+)",  # RFC 2822
                    r"(\d+-\d+-\d+\s+\d+:\d+:\d+)",  # ISO 8601 date
                    r"(\d+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)",  # Common email format
                ]
                
                for pattern in timestamp_patterns:
                    matches = re.findall(pattern, header_value)
                    for timestamp in matches:
                        timestamps.append({
                            "timestamp": timestamp,
                            "source": header_name
                        })
        
        return timestamps
    
    def check_spam_indicators(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for spam indicators in headers"""
        indicators = []
        
        # Check for suspicious headers
        suspicious_headers = {
            "X-Spam-Score": "Spam score detected",
            "X-Spam-Flag": "Spam flag detected",
            "X-Spam-Status": "Spam status detected",
            "X-BeenThere": "Possible mailing list",
            "X-Mailman-Version": "Mailing list software",
            "X-Mailer": "Mailer software",
            "X-Priority": "Priority flag",
        }
        
        for header_name, header_value in headers.items():
            if header_name in suspicious_headers:
                indicators.append({
                    "type": "suspicious_header",
                    "header": header_name,
                    "value": header_value,
                    "description": suspicious_headers[header_name]
                })
        
        # Check for open relay indicators
        if "Received" in headers:
            received_count = len([k for k in headers.keys() if "Received" in k])
            if received_count > 10:
                indicators.append({
                    "type": "too_many_received",
                    "count": received_count,
                    "description": "Excessive number of Received headers (possible relay)"
                })
        
        # Check for forged headers
        forging_indicators = [
            ("From", "To"),
            ("Reply-To", "From"),
        ]
        
        for from_header, to_header in forging_indicators:
            if from_header in headers and to_header in headers:
                if headers[from_header] == headers[to_header]:
                    indicators.append({
                        "type": "header_forging",
                        "headers": [from_header, to_header],
                        "description": f"{from_header} and {to_header} are identical (possible forgery)"
                    })
        
        # Check for suspicious User-Agent
        if "User-Agent" in headers:
            user_agent = headers["User-Agent"].lower()
            suspicious_agents = [
                "python-requests",
                "curl",
                "wget",
                "postman",
                "java",
                "php",
            ]
            
            for agent in suspicious_agents:
                if agent in user_agent:
                    indicators.append({
                        "type": "suspicious_user_agent",
                        "user_agent": headers["User-Agent"],
                        "description": "Suspicious User-Agent detected"
                    })
                    break
        
        return indicators
    
    def detect_anomalies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in header analysis"""
        anomalies = []
        
        # Check for IP reputation
        for ip_info in data["ips"]:
            ip = ip_info["ip"]
            
            # Check if IP is in known bad ranges
            bad_ranges = [
                ("192.168.0.0", "192.168.255.255", "Private IP"),
                ("10.0.0.0", "10.255.255.255", "Private IP"),
                ("172.16.0.0", "172.31.255.255", "Private IP"),
                ("127.0.0.0", "127.255.255.255", "Loopback"),
            ]
            
            for start_ip, end_ip, description in bad_ranges:
                if self.ip_in_range(ip, start_ip, end_ip):
                    anomalies.append({
                        "type": "private_ip",
                        "ip": ip,
                        "description": f"{description} detected in headers"
                    })
                    break
        
        # Check for timestamp anomalies
        if len(data["timestamps"]) > 1:
            # Check if timestamps are in order
            # This is a simplified check
            timestamps = data["timestamps"]
            if len(timestamps) > 1:
                # Check if any timestamp is significantly in the future
                # (This would require actual date parsing)
                pass
        
        # Check for missing headers
        required_headers = ["From", "To", "Date", "Subject"]
        parsed_headers = data["parsed"]
        
        for header in required_headers:
            if header not in parsed_headers:
                anomalies.append({
                    "type": "missing_header",
                    "header": header,
                    "description": f"Required header {header} is missing"
                })
        
        return anomalies
    
    def analyze_header_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze header data"""
        analysis = {
            "ip_count": len(data["ips"]),
            "server_count": len(data["servers"]),
            "routing_hops": len(data["routing"]),
            "timestamp_count": len(data["timestamps"]),
            "spam_indicator_count": len(data["spam_indicators"]),
            "anomaly_count": len(data["anomalies"]),
            "unique_ips": len(set([ip["ip"] for ip in data["ips"]])),
            "first_hop": data["routing"][0] if data["routing"] else None,
            "last_hop": data["routing"][-1] if data["routing"] else None,
            "is_suspicious": False,
            "risk_level": "low",
            "recommendations": []
        }
        
        # Determine if suspicious
        if analysis["anomaly_count"] > 0 or analysis["spam_indicator_count"] > 0:
            analysis["is_suspicious"] = True
        
        # Determine risk level
        if analysis["anomaly_count"] > 3:
            analysis["risk_level"] = "critical"
        elif analysis["anomaly_count"] > 1 or analysis["spam_indicator_count"] > 2:
            analysis["risk_level"] = "high"
        elif analysis["anomaly_count"] > 0 or analysis["spam_indicator_count"] > 0:
            analysis["risk_level"] = "medium"
        
        # Generate recommendations
        if analysis["is_suspicious"]:
            analysis["recommendations"].append(
                f"Suspicious email detected with {analysis['anomaly_count']} anomalies and {analysis['spam_indicator_count']} spam indicators"
            )
        else:
            analysis["recommendations"].append(
                "No suspicious indicators detected"
            )
        
        if analysis["ip_count"] > 5:
            analysis["recommendations"].append(
                f"Multiple IPs ({analysis['ip_count']}) detected in headers - check for relays"
            )
        
        if analysis["routing_hops"] > 10:
            analysis["recommendations"].append(
                f"Excessive routing hops ({analysis['routing_hops']}) - possible relay or spoofing"
            )
        
        if analysis["unique_ips"] > analysis["ip_count"] / 2:
            analysis["recommendations"].append(
                f"Multiple unique IPs ({analysis['unique_ips']}) - check for spoofing"
            )
        
        # Check for private IPs
        private_ips = [a for a in data["anomalies"] if a.get("type") == "private_ip"]
        if private_ips:
            analysis["recommendations"].append(
                f"Private IP addresses detected in headers - possible internal relay"
            )
        
        return analysis
    
    def validate_ip(self, ip: str) -> bool:
        """Validate an IP address"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    def ip_in_range(self, ip: str, start_ip: str, end_ip: str) -> bool:
        """Check if an IP is in a range"""
        def ip_to_int(ip_str: str) -> int:
            parts = list(map(int, ip_str.split(".")))
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        ip_int = ip_to_int(ip)
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        
        return start_int <= ip_int <= end_int
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's an email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, target):
            return TargetType.EMAIL
        
        return None


# Module instance
header_forensics_module = HeaderForensicsModule
