"""
Port Knocking Module for SHADOWSCOPE
Performs stealthy port knocking and service detection.
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
import socket
import ssl

from shadowscope.core.modules import BaseModule, ModuleResult, ModuleConfig
from shadowscope.core.targets import TargetType
from shadowscope.core import proxy, cache

console = Console()


@dataclass
class PortKnockingConfig(ModuleConfig):
    """Configuration for port knocking module"""
    common_ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
        993, 995, 1080, 1433, 1434, 1521, 1723, 3128, 3268, 3306, 3389,
        5432, 5900, 6379, 6566, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
        9090, 9200, 9300, 11211, 27017, 27018, 28017
    ])
    stealth_ports: List[int] = field(default_factory=lambda: [
        80, 443, 8080, 8443
    ])
    timeout: float = 5.0
    use_proxy: bool = False  # Port scanning doesn't typically use proxies
    max_concurrent: int = 100
    scan_timeout: float = 10.0
    retries: int = 2
    ssl_check: bool = True
    service_detection: bool = True
    banner_grab: bool = True
    
    def __post_init__(self):
        # Ensure unique ports
        self.common_ports = list(set(self.common_ports))
        self.stealth_ports = list(set(self.stealth_ports))


class PortKnockingModule(BaseModule):
    """
    Port Knocking Module
    
    Performs stealthy port scanning and service detection on target IPs.
    Uses non-intrusive techniques to avoid detection while gathering information.
    """
    
    MODULE_NAME = "port_knocking"
    MODULE_VERSION = "1.0.0"
    MODULE_AUTHOR = "SHADOWSCOPE"
    MODULE_CATEGORY = "IP/Network"
    MODULE_DESCRIPTION = "Stealthy port knocking and service detection"
    MODULE_TARGET_TYPES = [TargetType.IP]
    
    DEFAULT_CONFIG = PortKnockingConfig
    
    def __init__(self, config: Optional[PortKnockingConfig] = None):
        super().__init__(config or PortKnockingConfig())
        self.session: Optional[aiohttp.ClientSession] = None
        self.open_ports: List[int] = []
        self.services: Dict[int, Dict[str, Any]] = {}
    
    async def initialize(self) -> None:
        """Initialize the module"""
        connector = aiohttp.TCPConnector(
            ssl=self.config.ssl_check,
            limit=self.config.max_concurrent
        )
        timeout = aiohttp.ClientTimeout(total=self.config.scan_timeout)
        
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
        """Execute the port knocking module"""
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
            
            # Check cache
            cache_key = f"port_knocking:{target}"
            cached = cache.get(cache_key)
            if cached:
                result.status = "cached"
                result.data = cached
                return result
            
            # Initialize
            await self.initialize()
            
            # Scan ports
            scan_data = await self.scan_ports(target)
            
            # Store in cache
            cache.set(cache_key, scan_data, ttl=3600)  # 1 hour
            
            result.status = "success"
            result.data = scan_data
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.end_time = datetime.utcnow()
        finally:
            if self.session:
                await self.session.close()
        
        return result
    
    async def scan_ports(self, ip: str) -> Dict[str, Any]:
        """Scan ports on the target IP"""
        data = {
            "ip": ip,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "ports": {},
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "analysis": {}
        }
        
        # Use stealth mode if configured
        if self.config.stealth_ports:
            ports_to_scan = self.config.stealth_ports
        else:
            ports_to_scan = self.config.common_ports
        
        # Scan ports
        scan_results = await self.scan_port_list(ip, ports_to_scan)
        
        for port, status in scan_results.items():
            data["ports"][port] = {
                "status": status,
                "service": None,
                "banner": None,
                "ssl": None
            }
            
            if status == "open":
                data["open_ports"].append(port)
                
                # Detect service
                if self.config.service_detection:
                    service_info = await self.detect_service(ip, port)
                    if service_info:
                        data["ports"][port]["service"] = service_info.get("service")
                        data["ports"][port]["version"] = service_info.get("version")
                        
                        # Grab banner
                        if self.config.banner_grab:
                            banner = await self.grab_banner(ip, port)
                            if banner:
                                data["ports"][port]["banner"] = banner
                        
                        # Check SSL
                        if self.config.ssl_check and port in [443, 8443, 9443]:
                            ssl_info = await self.check_ssl(ip, port)
                            if ssl_info:
                                data["ports"][port]["ssl"] = ssl_info
            elif status == "closed":
                data["closed_ports"].append(port)
            else:
                data["filtered_ports"].append(port)
        
        # Build services dict
        data["services"] = {
            port: data["ports"][port] 
            for port in data["open_ports"]
        }
        
        # Analyze the data
        data["analysis"] = self.analyze_scan_data(data)
        
        return data
    
    async def scan_port_list(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Scan a list of ports and return their status"""
        results = {}
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        async def scan_port(port: int) -> Tuple[int, str]:
            try:
                # Try TCP connection
                reader, writer = await asyncio.open_connection(
                    ip, port, 
                    ssl=None,
                    family=socket.AF_INET
                )
                writer.close()
                await writer.wait_closed()
                return port, "open"
            except ConnectionRefusedError:
                return port, "closed"
            except asyncio.TimeoutError:
                return port, "filtered"
            except Exception:
                return port, "filtered"
        
        # Scan ports concurrently
        tasks = []
        for port in ports:
            task = asyncio.create_task(self.safe_scan_port(semaphore, scan_port, ip, port))
            tasks.append(task)
        
        # Wait for all scans to complete
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in completed:
            if isinstance(result, tuple):
                port, status = result
                results[port] = status
            else:
                # Handle exceptions
                console.print(f"[yellow]Warning: Port scan error: {result}[/yellow]")
        
        return results
    
    async def safe_scan_port(self, semaphore: asyncio.Semaphore, 
                           scan_func, ip: str, port: int) -> Tuple[int, str]:
        """Safely scan a port with semaphore"""
        async with semaphore:
            try:
                return await scan_func(port)
            except Exception as e:
                console.print(f"[yellow]Warning: Error scanning port {port}: {e}[/yellow]")
                return port, "error"
    
    async def detect_service(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Detect service running on a port"""
        # Common port to service mappings
        common_services = {
            21: ("ftp", "FTP"),
            22: ("ssh", "SSH"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "SMTP"),
            53: ("dns", "DNS"),
            80: ("http", "HTTP"),
            110: ("pop3", "POP3"),
            111: ("rpcbind", "RPC Bind"),
            135: ("msrpc", "Microsoft RPC"),
            139: ("netbios", "NetBIOS"),
            143: ("imap", "IMAP"),
            443: ("https", "HTTPS"),
            445: ("smb", "SMB"),
            465: ("smtp", "SMTP SSL"),
            587: ("smtp", "SMTP Submission"),
            993: ("imap", "IMAP SSL"),
            995: ("pop3", "POP3 SSL"),
            1080: ("socks", "SOCKS Proxy"),
            1433: ("mysql", "MySQL"),
            1434: ("ms-sql-m", "Microsoft SQL Monitor"),
            1521: ("oracle", "Oracle Database"),
            1723: ("pptp", "PPTP VPN"),
            3128: ("http-proxy", "HTTP Proxy"),
            3268: ("ldap", "LDAP"),
            3306: ("mysql", "MySQL"),
            3389: ("rdp", "Remote Desktop"),
            5432: ("postgresql", "PostgreSQL"),
            5900: ("vnc", "VNC"),
            6379: ("redis", "Redis"),
            6566: ("sane", "SANE"),
            8000: ("http-alt", "HTTP Alternate"),
            8008: ("http-alt", "HTTP Alternate"),
            8080: ("http-proxy", "HTTP Proxy"),
            8081: ("http-alt", "HTTP Alternate"),
            8443: ("https-alt", "HTTPS Alternate"),
            8888: ("http-alt", "HTTP Alternate"),
            9000: ("php-fpm", "PHP FPM"),
            9090: ("webmin", "Webmin"),
            9200: ("elasticsearch", "Elasticsearch"),
            9300: ("elasticsearch", "Elasticsearch Cluster"),
            11211: ("memcached", "Memcached"),
            27017: ("mongodb", "MongoDB"),
            27018: ("mongodb", "MongoDB"),
            28017: ("mongodb", "MongoDB")
        }
        
        # Check if port is in common services
        if port in common_services:
            service_name, service_desc = common_services[port]
            return {
                "service": service_name,
                "description": service_desc,
                "port": port
            }
        
        # Try to connect and grab banner for service detection
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            
            # Send a simple probe
            probe_data = b"\r\n\r\n"
            writer.write(probe_data)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            # Analyze response
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check for common service banners
            service_signatures = {
                "SSH": b"SSH-",
                "HTTP": b"HTTP/",
                "HTTPS": b"HTTP/",
                "FTP": b"220 ",
                "SMTP": b"220 ",
                "POP3": b"+OK",
                "IMAP": b"* OK",
                "Redis": b"-ERR",
                "MongoDB": b"MongoDB",
                "MySQL": b"MySQL",
                "PostgreSQL": b"PostgreSQL",
            }
            
            for service, signature in service_signatures.items():
                if signature in response:
                    return {
                        "service": service.lower(),
                        "description": service,
                        "port": port,
                        "detected_from": "banner"
                    }
            
        except Exception:
            pass
        
        return None
    
    async def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from a service"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            
            # Send a simple probe
            probe_data = b"\r\n\r\n"
            writer.write(probe_data)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            # Clean up the banner
            banner = response.decode('utf-8', errors='ignore')
            banner = banner.strip()
            
            if banner:
                return banner
            
        except Exception:
            pass
        
        return None
    
    async def check_ssl(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Check SSL certificate on a port"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.open_connection(
                ip, port, 
                ssl=context
            )
            
            # Get certificate
            cert = writer.get_extra_info('ssl_object').getpeercert()
            
            if cert:
                ssl_info = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "serialNumber": cert.get('serialNumber'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "version": cert.get('version'),
                }
                
                writer.close()
                await writer.wait_closed()
                
                return ssl_info
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass
        
        return None
    
    def analyze_scan_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze port scan data"""
        analysis = {
            "ip": data["ip"],
            "open_ports_count": len(data["open_ports"]),
            "closed_ports_count": len(data["closed_ports"]),
            "filtered_ports_count": len(data["filtered_ports"]),
            "services_count": len(data["services"]),
            "vulnerable_ports": [],
            "exposed_services": [],
            "recommendations": []
        }
        
        # Check for vulnerable services
        vulnerable_ports = {
            21: "FTP - often vulnerable to brute force",
            22: "SSH - check for weak credentials",
            23: "Telnet - insecure protocol",
            25: "SMTP - check for open relay",
            110: "POP3 - often vulnerable to brute force",
            135: "RPC - often vulnerable to exploits",
            139: "NetBIOS - SMB vulnerabilities",
            143: "IMAP - check for weak credentials",
            445: "SMB - EternalBlue and other vulnerabilities",
            1433: "MySQL - check for weak credentials",
            1434: "MS SQL - check for weak credentials",
            1521: "Oracle - check for default credentials",
            3306: "MySQL - check for weak credentials",
            3389: "RDP - check for weak credentials",
            5432: "PostgreSQL - check for weak credentials",
            5900: "VNC - check for weak credentials",
            6379: "Redis - check for unauthenticated access",
            9200: "Elasticsearch - check for unauthenticated access",
            11211: "Memcached - check for unauthenticated access",
            27017: "MongoDB - check for unauthenticated access"
        }
        
        for port in data["open_ports"]:
            if port in vulnerable_ports:
                analysis["vulnerable_ports"].append({
                    "port": port,
                    "service": data["ports"][port].get("service"),
                    "risk": vulnerable_ports[port]
                })
        
        # Check for exposed services
        exposed_ports = {
            80: "HTTP - web server exposed",
            443: "HTTPS - web server exposed",
            8000: "HTTP Alternate - web server exposed",
            8080: "HTTP Proxy - web server exposed",
            8443: "HTTPS Alternate - web server exposed",
            22: "SSH - remote access exposed",
            3389: "RDP - remote desktop exposed",
            5900: "VNC - remote desktop exposed",
            3306: "MySQL - database exposed",
            5432: "PostgreSQL - database exposed",
            27017: "MongoDB - database exposed",
            6379: "Redis - cache exposed",
            11211: "Memcached - cache exposed",
            9200: "Elasticsearch - search exposed",
            1521: "Oracle - database exposed",
            1433: "MS SQL - database exposed"
        }
        
        for port in data["open_ports"]:
            if port in exposed_ports:
                analysis["exposed_services"].append({
                    "port": port,
                    "service": data["ports"][port].get("service"),
                    "risk": exposed_ports[port]
                })
        
        # Generate recommendations
        if analysis["vulnerable_ports"]:
            analysis["recommendations"].append(
                f"VULNERABLE: {len(analysis['vulnerable_ports'])} vulnerable services detected"
            )
        
        if analysis["exposed_services"]:
            analysis["recommendations"].append(
                f"EXPOSED: {len(analysis['exposed_services'])} services exposed to internet"
            )
        
        if analysis["open_ports_count"] > 10:
            analysis["recommendations"].append(
                f"Multiple open ports ({analysis['open_ports_count']}) - consider reducing attack surface"
            )
        
        if analysis["open_ports_count"] == 0:
            analysis["recommendations"].append(
                "No open ports detected - target may be behind firewall"
            )
        
        # Check for specific high-risk services
        high_risk_ports = [445, 1433, 3306, 3389, 5900, 22]
        high_risk_count = sum(1 for p in data["open_ports"] if p in high_risk_ports)
        
        if high_risk_count > 0:
            analysis["recommendations"].append(
                f"HIGH RISK: {high_risk_count} high-risk services exposed"
            )
        
        return analysis
    
    def validate_target(self, target: str) -> Optional[TargetType]:
        """Validate target and return its type"""
        import re
        
        # Check if it's an IP
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            return TargetType.IP
        
        return None


# Module instance
port_knocking_module = PortKnockingModule
