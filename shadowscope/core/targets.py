"""
Target Management System for SHADOWSCOPE
Handles target classification, deduplication, and scope management.
"""

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import threading

console = Console()


@dataclass
class Target:
    """Represents an investigation target with full metadata"""
    value: str
    target_type: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"
    id: Optional[int] = None
    
    def __post_init__(self):
        """Auto-detect type if not specified"""
        if self.target_type == "unknown":
            self.target_type = self._detect_type(self.value)
    
    @staticmethod
    def _detect_type(value: str) -> str:
        """Auto-detect target type from value"""
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "email"
        
        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        
        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "domain"
        
        # IP address (IPv4)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            # Validate it's a real IP
            parts = value.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return "ip"
        
        # IPv6
        if re.match(r'^[a-fA-F0-9:]+$', value) and ':' in value:
            return "ipv6"
        
        # Phone number (international format)
        if re.match(r'^\+?[0-9\s-]{10,15}$', value):
            return "phone"
        
        # Bitcoin address
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', value):
            return "bitcoin"
        
        # Ethereum address
        if re.match(r'^0x[a-fA-F0-9]{40}$', value):
            return "ethereum"
        
        # Litecoin address
        if re.match(r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$', value):
            return "litecoin"
        
        # Monero address
        if re.match(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', value):
            return "monero"
        
        # Onion address (v2 or v3)
        if value.endswith('.onion'):
            return "onion"
        
        # I2P address
        if value.endswith('.i2p'):
            return "i2p"
        
        # Username (simple detection - alphanumeric with underscores/dots)
        if re.match(r'^[a-zA-Z0-9_.-]{3,32}$', value):
            # Check if it looks like a domain (has dots)
            if '.' in value and value.count('.') >= 1:
                # Could be a domain without TLD
                pass
            else:
                return "username"
        
        # Vehicle VIN
        if re.match(r'^[A-HJ-NPR-Z0-9]{17}$', value):
            return "vin"
        
        # License plate (US format)
        if re.match(r'^[A-Z0-9]{2,8}$', value):
            return "license_plate"
        
        # Physical address (simplified detection)
        if re.match(r'^\d+\s+[A-Za-z\s]+', value):
            return "address"
        
        # File hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
            return "md5"
        if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
            return "sha1"
        if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
            return "sha256"
        
        # Default to unknown
        return "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "value": self.value,
            "target_type": self.target_type,
            "metadata": self.metadata,
            "tags": self.tags,
            "added_at": self.added_at,
            "updated_at": self.updated_at,
            "status": self.status
        }
    
    def __hash__(self):
        """Hash based on value for deduplication"""
        return hash(self.value.lower())
    
    def __eq__(self, other):
        """Equality based on value"""
        if isinstance(other, Target):
            return self.value.lower() == other.value.lower()
        return False
    
    def __str__(self):
        return f"{self.value} ({self.target_type})"


class TargetManager:
    """Manages the collection of targets and their lifecycle"""
    
    def __init__(self):
        from .storage import storage
        self.storage = storage
        self._targets: Dict[str, Target] = {}
        self._lock = threading.Lock()
        self._load_targets()
    
    def _load_targets(self):
        """Load targets from storage"""
        try:
            targets = self.storage.get_all_targets()
            for target in targets:
                self._targets[target.target.lower()] = Target(
                    value=target.target,
                    target_type=target.target_type,
                    metadata=target.metadata,
                    tags=target.tags,
                    added_at=target.added_at,
                    updated_at=target.updated_at,
                    status=target.status,
                    id=target.id
                )
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load targets from storage: {e}[/yellow]")
    
    def add(self, target: Union[str, Target], tags: Optional[List[str]] = None, 
            metadata: Optional[Dict[str, Any]] = None, **kwargs) -> Target:
        """Add a target to the scope"""
        with self._lock:
            # Convert string to Target object
            if isinstance(target, str):
                target_obj = Target(value=target, tags=tags or [], metadata=metadata or {})
            else:
                target_obj = target
            
            # Normalize value
            normalized = target_obj.value.lower().strip()
            
            # Check for duplicates
            if normalized in self._targets:
                existing = self._targets[normalized]
                # Update existing target
                if tags:
                    existing.tags = list(set(existing.tags + tags))
                if metadata:
                    existing.metadata.update(metadata)
                existing.updated_at = datetime.now().isoformat()
                
                # Update in storage
                self.storage.update_target(existing.id, 
                                           tags=existing.tags,
                                           metadata=existing.metadata,
                                           updated_at=existing.updated_at)
                return existing
            
            # Add new target
            target_obj.value = target_obj.value.strip()
            target_obj.tags = list(set(target_obj.tags + (tags or [])))
            if metadata:
                target_obj.metadata.update(metadata)
            
            # Store in database
            stored_target = self.storage.add_target(
                target=target_obj.value,
                target_type=target_obj.target_type,
                tags=target_obj.tags,
                metadata=target_obj.metadata
            )
            
            target_obj.id = stored_target.id
            target_obj.added_at = stored_target.added_at
            target_obj.updated_at = stored_target.updated_at
            
            # Add to memory
            self._targets[normalized] = target_obj
            
            console.print(f"[green]+[/green] Added target: {target_obj}")
            
            return target_obj
    
    def add_bulk(self, targets: List[Union[str, Target]], 
                 tags: Optional[List[str]] = None, 
                 metadata: Optional[Dict[str, Any]] = None) -> List[Target]:
        """Add multiple targets at once"""
        added = []
        for target in targets:
            added.append(self.add(target, tags=tags, metadata=metadata))
        return added
    
    def remove(self, target: Union[str, Target]) -> bool:
        """Remove a target from scope"""
        with self._lock:
            if isinstance(target, str):
                normalized = target.lower().strip()
                target_obj = self._targets.get(normalized)
            else:
                normalized = target.value.lower().strip()
                target_obj = target
            
            if target_obj and target_obj.id:
                success = self.storage.delete_target(target_obj.id)
                if success:
                    self._targets.pop(normalized, None)
                    console.print(f"[red]-[/red] Removed target: {target_obj}")
                    return True
            return False
    
    def get(self, target: Union[str, int]) -> Optional[Target]:
        """Get a target by value or ID"""
        with self._lock:
            if isinstance(target, int):
                stored = self.storage.get_target(target)
                if stored:
                    return Target(
                        value=stored.target,
                        target_type=stored.target_type,
                        metadata=stored.metadata,
                        tags=stored.tags,
                        added_at=stored.added_at,
                        updated_at=stored.updated_at,
                        status=stored.status,
                        id=stored.id
                    )
            else:
                normalized = target.lower().strip()
                return self._targets.get(normalized)
        return None
    
    def get_all(self, target_type: Optional[str] = None, 
                status: Optional[str] = None, 
                tags: Optional[List[str]] = None) -> List[Target]:
        """Get all targets with optional filters"""
        with self._lock:
            targets = list(self._targets.values())
            
            # Filter by type
            if target_type:
                targets = [t for t in targets if t.target_type == target_type]
            
            # Filter by status
            if status:
                targets = [t for t in targets if t.status == status]
            
            # Filter by tags
            if tags:
                tag_set = set(tags)
                targets = [t for t in targets if tag_set.issubset(set(t.tags))]
            
            return sorted(targets, key=lambda x: x.added_at, reverse=True)
    
    def update(self, target: Union[str, Target], **kwargs) -> bool:
        """Update target properties"""
        with self._lock:
            if isinstance(target, str):
                target_obj = self.get(target)
            else:
                target_obj = target
            
            if not target_obj:
                return False
            
            # Update fields
            for key, value in kwargs.items():
                if hasattr(target_obj, key):
                    setattr(target_obj, key, value)
            
            target_obj.updated_at = datetime.now().isoformat()
            
            # Update in storage
            if target_obj.id:
                update_data = {k: v for k, v in kwargs.items() if k in ['tags', 'metadata', 'status']}
                update_data['updated_at'] = target_obj.updated_at
                self.storage.update_target(target_obj.id, **update_data)
            
            return True
    
    def clear(self) -> int:
        """Clear all targets"""
        with self._lock:
            count = len(self._targets)
            for target in list(self._targets.values()):
                if target.id:
                    self.storage.delete_target(target.id)
            self._targets.clear()
            console.print(f"[yellow]![/yellow] Cleared {count} targets")
            return count
    
    def count(self, target_type: Optional[str] = None) -> int:
        """Count targets"""
        if target_type:
            return len([t for t in self._targets.values() if t.target_type == target_type])
        return len(self._targets)
    
    def search(self, query: str, limit: int = 50) -> List[Target]:
        """Search targets by value or metadata"""
        query = query.lower()
        results = []
        
        for target in self._targets.values():
            if query in target.value.lower():
                results.append(target)
            elif query in json.dumps(target.metadata).lower():
                results.append(target)
            elif any(query in tag.lower() for tag in target.tags):
                results.append(target)
            
            if len(results) >= limit:
                break
        
        return results
    
    def tag(self, targets: List[Union[str, Target]], tags: List[str]) -> int:
        """Add tags to multiple targets"""
        count = 0
        for target in targets:
            target_obj = self.get(target) if isinstance(target, str) else target
            if target_obj:
                target_obj.tags = list(set(target_obj.tags + tags))
                target_obj.updated_at = datetime.now().isoformat()
                
                if target_obj.id:
                    self.storage.update_target(
                        target_obj.id,
                        tags=target_obj.tags,
                        updated_at=target_obj.updated_at
                    )
                count += 1
        
        console.print(f"[blue]#[/blue] Tagged {count} targets with: {tags}")
        return count
    
    def untag(self, targets: List[Union[str, Target]], tags: List[str]) -> int:
        """Remove tags from multiple targets"""
        count = 0
        for target in targets:
            target_obj = self.get(target) if isinstance(target, str) else target
            if target_obj:
                target_obj.tags = [t for t in target_obj.tags if t not in tags]
                target_obj.updated_at = datetime.now().isoformat()
                
                if target_obj.id:
                    self.storage.update_target(
                        target_obj.id,
                        tags=target_obj.tags,
                        updated_at=target_obj.updated_at
                    )
                count += 1
        
        console.print(f"[blue]#[/blue] Removed tags from {count} targets: {tags}")
        return count
    
    def get_by_type(self, target_type: str) -> List[Target]:
        """Get all targets of a specific type"""
        return [t for t in self._targets.values() if t.target_type == target_type]
    
    def get_types(self) -> Set[str]:
        """Get all unique target types in scope"""
        return {t.target_type for t in self._targets.values()}
    
    def get_tags(self) -> Set[str]:
        """Get all unique tags in scope"""
        tags = set()
        for target in self._targets.values():
            tags.update(target.tags)
        return tags
    
    def validate_targets(self) -> Dict[str, List[str]]:
        """Validate all targets and return issues"""
        issues = {"invalid": [], "duplicate": []}
        seen = set()
        
        for target in self._targets.values():
            # Check for duplicates
            normalized = target.value.lower().strip()
            if normalized in seen:
                issues["duplicate"].append(target.value)
            seen.add(normalized)
            
            # Validate based on type
            if target.target_type == "email":
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target.value):
                    issues["invalid"].append(f"{target.value} (invalid email)")
            elif target.target_type == "ip":
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target.value):
                    issues["invalid"].append(f"{target.value} (invalid IP)")
            elif target.target_type == "domain":
                if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target.value):
                    issues["invalid"].append(f"{target.value} (invalid domain)")
        
        return issues
    
    def import_from_file(self, file_path: str, target_type: Optional[str] = None) -> int:
        """Import targets from a file (CSV, JSON, or text)"""
        file_path = Path(file_path)
        count = 0
        
        if not file_path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            return 0
        
        content = file_path.read_text()
        
        if file_path.suffix == '.json':
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            self.add(item, tags=["imported"])
                            count += 1
                        elif isinstance(item, dict):
                            target = item.get('value') or item.get('target')
                            if target:
                                self.add(target, 
                                        tags=item.get('tags', ["imported"]),
                                        metadata=item.get('metadata'))
                                count += 1
            except json.JSONDecodeError as e:
                console.print(f"[red]Error parsing JSON: {e}[/red]")
        
        elif file_path.suffix == '.csv':
            import csv
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:  # Skip empty rows
                        target = row[0].strip()
                        if target:
                            tags = ["imported"]
                            if len(row) > 1:
                                tags.extend([t.strip() for t in row[1:] if t.strip()])
                            self.add(target, tags=tags)
                            count += 1
        
        else:  # Text file - one target per line
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    self.add(line, tags=["imported"])
                    count += 1
        
        console.print(f"[green]+[/green] Imported {count} targets from {file_path}")
        return count
    
    def export_to_file(self, file_path: str, format: str = "text") -> str:
        """Export targets to a file"""
        file_path = Path(file_path)
        targets = self.get_all()
        
        if format == "json":
            data = [t.to_dict() for t in targets]
            file_path.write_text(json.dumps(data, indent=2, default=str))
        
        elif format == "csv":
            import csv
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Value', 'Type', 'Tags', 'Added At'])
                for target in targets:
                    writer.writerow([
                        target.value,
                        target.target_type,
                        ';'.join(target.tags),
                        target.added_at
                    ])
        
        else:  # Text format
            lines = []
            for target in targets:
                tags = f" [{', '.join(target.tags)}]" if target.tags else ""
                lines.append(f"{target.value} ({target.target_type}){tags}")
            file_path.write_text('\n'.join(lines))
        
        console.print(f"[green]+[/green] Exported {len(targets)} targets to {file_path}")
        return str(file_path)
    
    def display_table(self, limit: int = 50):
        """Display targets in a rich table"""
        table = Table(title="Current Scope Targets", show_header=True, header_style="bold blue")
        table.add_column("ID", style="dim")
        table.add_column("Target", style="green")
        table.add_column("Type", style="cyan")
        table.add_column("Tags", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Added", style="dim")
        
        targets = self.get_all()[:limit]
        
        for target in targets:
            tags = ", ".join(target.tags) if target.tags else "-"
            status_style = "green" if target.status == "completed" else "yellow" if target.status == "processing" else "dim"
            
            table.add_row(
                str(target.id) if target.id else "-",
                target.value,
                target.target_type,
                tags,
                f"[{status_style}]{target.status}[/{status_style}]",
                target.added_at[:10] if target.added_at else "-"
            )
        
        if len(self._targets) > limit:
            table.add_row(
                f"[dim]... and {len(self._targets) - limit} more[/dim]",
                "", "", "", "", ""
            )
        
        console.print(table)
        console.print(f"[dim]Total: {len(self._targets)} targets[/dim]")


# Initialize target manager
targets = TargetManager()
