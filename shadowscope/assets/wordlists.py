"""
SHADOWSCOPE Wordlists
Pre-defined wordlists for various OSINT tasks
"""

from typing import List

# DNS Wordlist (Common subdomains)
DNS_WORDLIST: List[str] = [
    # Common
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3", "ns4",
    "webmail", "admin", "test", "dev", "beta", "staging", "api", "app", "apps",
    
    # Development
    "dev", "development", "stage", "staging", "qa", "testing", "demo", "sandbox",
    
    # Services
    "blog", "news", "forum", "shop", "store", "cart", "checkout", "pay", "payment",
    "support", "help", "docs", "documentation", "wiki", "status", "health",
    
    # Infrastructure
    "cdn", "static", "assets", "media", "images", "img", "video", "download",
    "upload", "files", "data", "db", "database", "sql", "mysql", "postgres",
    
    # Security
    "secure", "ssl", "vpn", "proxy", "gateway", "auth", "login", "logout",
    "register", "signup", "account", "user", "users", "profile", "settings",
    
    # Monitoring
    "monitor", "stats", "metrics", "analytics", "logs", "log", "dashboard",
    
    # Mobile
    "mobile", "m", "api", "rest", "graphql", "json", "xml", "rss", "atom",
    
    # Cloud
    "cloud", "aws", "azure", "gcp", "google", "amazon", "microsoft", "ibm",
    
    # Version control
    "git", "svn", "hg", "code", "repo", "repos", "repository",
    
    # CI/CD
    "ci", "cd", "build", "deploy", "jenkins", "travis", "circleci", "github",
    
    # Containers
    "docker", "kubernetes", "k8s", "container", "pod", "service", "ingress",
    
    # Network
    "network", "net", "lan", "wan", "vpn", "firewall", "router", "switch",
    
    # VoIP
    "voip", "sip", "asterisk", "phone", "call", "conference", "meet",
    
    # Email
    "email", "mail", "smtp", "pop", "imap", "exchange", "outlook", "gmail",
    
    # Social
    "social", "facebook", "twitter", "instagram", "linkedin", "youtube", "reddit",
    
    # Admin panels
    "admin", "administrator", "cpanel", "whm", "plesk", "directadmin", "webmin",
    "phpmyadmin", "phpadmin", "myadmin", "mysql", "pma",
    
    # CMS
    "wordpress", "wp", "joomla", "drupal", "magento", "shopify", "ghost",
    "typo3", "concrete5", "opencart", "prestashop",
    
    # Frameworks
    "django", "flask", "rails", "laravel", "symfony", "spring", "express",
    "node", "react", "angular", "vue", "ember", "backbone",
    
    # Databases
    "mongo", "mongodb", "redis", "memcached", "elasticsearch", "solr",
    "cassandra", "couchdb", "postgresql", "mysql", "mariadb", "oracle",
    
    # APIs
    "api", "rest", "graphql", "soap", "json", "xml", "rpc", "grpc",
    
    # Tools
    "tools", "utility", "utils", "lib", "libs", "library", "bin", "sbin",
    
    # Misc
    "www1", "www2", "www3", "www4", "old", "new", "2020", "2021", "2022",
    "2023", "2024", "2025", "v1", "v2", "v3", "v4", "alpha", "beta",
    "gamma", "delta", "prod", "production", "live", "backup", "bkp",
]

# Extended Subdomain Wordlist
SUBDOMAIN_WORDLIST: List[str] = DNS_WORDLIST + [
    # Additional common subdomains
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    
    # Numbers
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
    "13", "14", "15", "16", "17", "18", "19", "20",
    
    # Colors
    "red", "green", "blue", "yellow", "black", "white", "orange", "purple",
    "pink", "brown", "gray", "grey",
    
    # Locations
    "us", "uk", "eu", "de", "fr", "es", "it", "nl", "be", "ch",
    "ca", "au", "nz", "jp", "cn", "in", "br", "mx",
    
    # Languages
    "en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
    
    # Regions
    "north", "south", "east", "west", "central", "northwest", "northeast",
    "southwest", "southeast",
    
    # Types
    "public", "private", "internal", "external", "corporate", "personal",
    "business", "company", "organization", "team", "group",
    
    # Status
    "active", "inactive", "archived", "legacy", "deprecated", "retired",
    
    # Environments
    "production", "prod", "preprod", "pre-production", "staging", "stage",
    "testing", "test", "development", "dev", "local",
    
    # Versions
    "v1", "v2", "v3", "v4", "v5", "version1", "version2", "version3",
    "latest", "current", "next", "old", "previous",
    
    # Geographic
    "america", "europe", "asia", "africa", "australia", "antarctica",
    "na", "sa", "af", "an", "as", "eu", "oc",
    
    # Time zones
    "utc", "gmt", "est", "cst", "mst", "pst", "akst", "hst",
    
    # Holidays
    "christmas", "easter", "thanksgiving", "newyear", "valentine",
    "halloween", "independence", "labour", "memorial",
    
    # Events
    "conference", "summit", "meeting", "webinar", "workshop", "seminar",
    "expo", "fair", "show", "event", "party",
    
    # Projects
    "project", "projects", "task", "tasks", "ticket", "tickets",
    "issue", "issues", "bug", "bugs", "feature", "features",
    
    # Products
    "product", "products", "service", "services", "solution", "solutions",
    "platform", "tool", "tools", "software", "app",
    
    # Industries
    "finance", "bank", "banking", "insurance", "health", "medical",
    "education", "school", "university", "college", "retail",
    "ecommerce", "travel", "hotel", "flight", "booking",
    
    # Technologies
    "tech", "technology", "innovation", "research", "development",
    "engineering", "design", "creative", "marketing", "sales",
    
    # Departments
    "it", "hr", "finance", "legal", "support", "sales", "marketing",
    "operations", "admin", "management", "executive",
]

# Username Wordlist (for social media enumeration)
USERNAME_WORDLIST: List[str] = [
    # Common patterns
    "admin", "administrator", "root", "user", "guest", "test", "demo",
    "superuser", "moderator", "manager", "owner", "ceo", "cto",
    
    # Name variations
    "john", "jane", "mike", "michael", "david", "james", "robert", "william",
    "mary", "jennifer", "lisa", "susan", "patricia", "linda", "elizabeth",
    
    # Common first names + numbers
    "john1", "john2", "john123", "mike1", "mike2", "david1", "james1",
    "mary1", "jane1", "lisa1", "susan1",
    
    # Leet speak variations
    "j0hn", "j0n", "j0hnny", "m1ke", "d4vid", "j4mes", "r0bert",
    "w1ll14m", "m4ry", "j3nn1f3r", "l1s4", "s3s4n",
    
    # Common prefixes
    "the", "my", "our", "new", "old", "best", "top", "real",
    
    # Common suffixes
    "official", "real", "true", "pro", "max", "king", "queen",
    "master", "boss", "guru", "ninja", "hacker", "expert",
    
    # Animals
    "lion", "tiger", "bear", "wolf", "eagle", "shark", "dragon",
    "snake", "fox", "panther", "jaguar", "leopard",
    
    # Colors + numbers
    "red1", "blue1", "green1", "black1", "white1",
    "red123", "blue123", "green123",
    
    # Sports
    "football", "soccer", "basketball", "baseball", "tennis",
    "hockey", "golf", "cricket", "rugby",
    
    # Games
    "player", "game", "gamer", "play", "chess", "poker",
    "minecraft", "fortnite", "callofduty", "gta",
    
    # Music
    "music", "dj", "singer", "artist", "band", "rock",
    "pop", "hiphop", "rap", "jazz", "blues",
    
    # Movies
    "movie", "film", "actor", "director", "star", "hero",
    "batman", "superman", "spiderman", "ironman",
    
    # Cars
    "car", "auto", "driver", "racer", "speed", "fast",
    "bmw", "mercedes", "audi", "ferrari", "lamborghini",
    
    # Tech terms
    "hacker", "coder", "dev", "programmer", "geek", "nerd",
    "tech", "it", "computer", "pc", "mac", "linux",
    
    # Fantasy
    "wizard", "warrior", "knight", "dragon", "elf", "dwarf",
    "mage", "sorcerer", "paladin", "ranger",
]

# Password Wordlist (for brute force attacks - use responsibly!)
PASSWORD_WORDLIST: List[str] = [
    # Common passwords (top 100)
    "password", "123456", "12345678", "1234", "qwerty", "12345",
    "dragon", "baseball", "football", "letmein", "monkey",
    "abc123", "mustang", "michael", "shadow", "master",
    "jennifer", "111111", "2000", "jordan", "superman",
    "harley", "1234567", "freedom", "whatever", "trustno1",
    
    # Common patterns
    "123456789", "1234567890", "123123", "11111111", "000000",
    "password1", "passw0rd", "p@ssword", "Password1", "Welcome1",
    "Admin123", "User123", "Guest123", "Test123",
    
    # Seasons
    "summer", "winter", "spring", "fall", "autumn",
    
    # Months
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    
    # Days
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
    
    # Numbers
    "123456789", "987654321", "121212", "112233", "123321",
    "654321", "666666", "888888", "999999",
    
    # Keyboard patterns
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e4r",
    "1qaz2wsx", "1q2w3e4r5t", "qazwsxedc",
    
    # Simple words
    "hello", "world", "welcome", "login", "admin", "user",
    "test", "guest", "access", "server", "root",
]

# Common Ports
COMMON_PORTS: List[int] = [
    # Well-known ports (0-1023)
    20,      # FTP data
    21,      # FTP control
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    53,      # DNS
    80,      # HTTP
    110,     # POP3
    119,     # NNTP
    123,     # NTP
    135,     # RPC
    139,     # NetBIOS
    143,     # IMAP
    161,     # SNMP
    162,     # SNMP Trap
    389,     # LDAP
    443,     # HTTPS
    445,     # SMB
    465,     # SMTP SSL
    514,     # Syslog
    515,     # LPD
    587,     # SMTP Submission
    631,     # IPP
    636,     # LDAP SSL
    993,     # IMAP SSL
    995,     # POP3 SSL
    
    # Registered ports (1024-49151)
    1080,    # SOCKS
    1433,    # MS SQL
    1521,    # Oracle
    1723,    # PPTP
    3128,    # HTTP Proxy
    3260,    # iSCSI
    3306,    # MySQL
    3389,    # RDP
    4333,    # mSQL
    5060,    # SIP
    5061,    # SIP TLS
    5222,    # XMPP Client
    5223,    # XMPP Server
    5269,    # XMPP Server Connection
    5357,    # WS-Discovery
    5432,    # PostgreSQL
    5601,    # Kibana
    5900,    # VNC
    6000,    # X11
    6379,    # Redis
    7000,    # FileMaker
    7070,    # RealServer
    8000,    # HTTP Alternate
    8008,    # HTTP Alternate
    8080,    # HTTP Proxy
    8081,    # HTTP Proxy
    8443,    # HTTPS Alternate
    8888,    # HTTP Alternate
    9000,    # PHP-FPM
    9001,    # Tor
    9050,    # Tor SOCKS
    9051,    # Tor Control
    9200,    # Elasticsearch
    9300,    # Elasticsearch
    11211,   # Memcached
    
    # Dynamic/Private ports (49152-65535)
    27017,   # MongoDB
    27018,   # MongoDB
    27019,   # MongoDB
]

# User Agents
USER_AGENTS: List[str] = [
    # Desktop - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    
    # Desktop - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    
    # Desktop - Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    
    # Mobile - iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    
    # Mobile - Android
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    
    # Mobile - Other
    "Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537",
    
    # Bots and Crawlers
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot2.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com)",
    
    # Legacy
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
]
