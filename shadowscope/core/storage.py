"""
Storage Layer for SHADOWSCOPE
Handles encrypted SQLite storage for all investigation data.
"""

import os
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import base64
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import threading

console = Console()


@dataclass
class Target:
    """Represents an investigation target"""
    id: Optional[int] = None
    target: str = ""
    target_type: str = "unknown"  # domain, ip, email, phone, url, etc.
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"  # pending, processing, completed, failed
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "target_type": self.target_type,
            "metadata": self.metadata,
            "tags": self.tags,
            "added_at": self.added_at,
            "updated_at": self.updated_at,
            "status": self.status
        }


@dataclass
class Result:
    """Represents a module result"""
    id: Optional[int] = None
    target_id: int = 0
    module: str = ""
    module_version: str = "1.0"
    data: Dict[str, Any] = field(default_factory=dict)
    status: str = "success"  # success, failed, partial
    error: Optional[str] = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "module": self.module,
            "module_version": self.module_version,
            "data": self.data,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at
        }


@dataclass
class ModuleInfo:
    """Represents module metadata"""
    id: Optional[int] = None
    name: str = ""
    version: str = "1.0"
    author: str = ""
    description: str = ""
    category: str = ""
    target_types: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    installed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "category": self.category,
            "target_types": self.target_types,
            "dependencies": self.dependencies,
            "config": self.config,
            "enabled": self.enabled,
            "installed_at": self.installed_at,
            "updated_at": self.updated_at
        }


class EncryptionManager:
    """Handles field-level encryption for sensitive data"""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.encryption_key = encryption_key
        self._fernet = None
        if self.encryption_key:
            self._fernet = Fernet(self.encryption_key)
    
    def encrypt(self, value: str) -> str:
        """Encrypt a value"""
        if not self._fernet:
            return value
        try:
            encrypted = self._fernet.encrypt(value.encode())
            return encrypted.decode()
        except:
            return value
    
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a value"""
        if not self._fernet:
            return encrypted_value
        try:
            decrypted = self._fernet.decrypt(encrypted_value.encode())
            return decrypted.decode()
        except:
            return encrypted_value
    
    def is_encrypted(self, value: str) -> bool:
        """Check if a value is encrypted"""
        return value.startswith('gAAAA')


class Storage:
    """Main storage class for SHADOWSCOPE"""
    
    def __init__(self, config=None):
        from .config import config as global_config
        self.config = config or global_config
        self.encryption = EncryptionManager(self.config._encryption_key)
        self._db_path = Path(self.config.storage.path).expanduser()
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize database and create tables"""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Enable WAL mode for better concurrency
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            
            # Create tables
            self._create_tables(conn)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection"""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Create all database tables"""
        # Targets table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                target_type TEXT NOT NULL DEFAULT 'unknown',
                metadata TEXT NOT NULL DEFAULT '{}',
                tags TEXT NOT NULL DEFAULT '[]',
                added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        """)
        
        # Results table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                module_version TEXT NOT NULL DEFAULT '1.0',
                data TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'success',
                error TEXT,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
            )
        """)
        
        # Modules table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                version TEXT NOT NULL DEFAULT '1.0',
                author TEXT,
                description TEXT,
                category TEXT,
                target_types TEXT NOT NULL DEFAULT '[]',
                dependencies TEXT NOT NULL DEFAULT '[]',
                config TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                installed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Indexes for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(target_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_added ON targets(added_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_module ON results(module)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON results(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_started ON results(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_modules_category ON modules(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_modules_enabled ON modules(enabled)")
    
    def _encrypt_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in data"""
        sensitive_fields = ['email', 'ip', 'phone', 'address', 'password', 'api_key', 'token', 'secret']
        
        def encrypt_value(value):
            if isinstance(value, str):
                for field in sensitive_fields:
                    if field in value.lower():
                        return self.encryption.encrypt(value)
                return value
            elif isinstance(value, dict):
                return {k: encrypt_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [encrypt_value(v) for v in value]
            return value
        
        return encrypt_value(data)
    
    def _decrypt_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields in data"""
        def decrypt_value(value):
            if isinstance(value, str):
                if self.encryption.is_encrypted(value):
                    return self.encryption.decrypt(value)
                return value
            elif isinstance(value, dict):
                return {k: decrypt_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [decrypt_value(v) for v in value]
            return value
        
        return decrypt_value(data)
    
    # Target CRUD operations
    
    def add_target(self, target: Union[str, Target], target_type: Optional[str] = None, 
                   tags: Optional[List[str]] = None, metadata: Optional[Dict[str, Any]] = None) -> Target:
        """Add a new target to the database"""
        if isinstance(target, str):
            target_obj = Target(
                target=target,
                target_type=target_type or self._detect_target_type(target),
                tags=tags or [],
                metadata=metadata or {},
                status="pending"
            )
        else:
            target_obj = target
        
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if target already exists
                cursor.execute("SELECT id FROM targets WHERE target = ?", (target_obj.target,))
                existing = cursor.fetchone()
                
                if existing:
                    target_obj.id = existing['id']
                    # Update existing target
                    cursor.execute("""
                        UPDATE targets SET 
                            target_type = ?,
                            metadata = ?,
                            tags = ?,
                            updated_at = CURRENT_TIMESTAMP,
                            status = ?
                        WHERE id = ?
                    """, (
                        target_obj.target_type,
                        json.dumps(target_obj.metadata),
                        json.dumps(target_obj.tags),
                        target_obj.status,
                        target_obj.id
                    ))
                else:
                    # Insert new target
                    cursor.execute("""
                        INSERT INTO targets (target, target_type, metadata, tags, added_at, updated_at, status)
                        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                    """, (
                        target_obj.target,
                        target_obj.target_type,
                        json.dumps(target_obj.metadata),
                        json.dumps(target_obj.tags),
                        target_obj.status
                    ))
                    target_obj.id = cursor.lastrowid
                
                conn.commit()
        
        return target_obj
    
    def _detect_target_type(self, target: str) -> str:
        """Auto-detect target type"""
        import re
        
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "email"
        
        # URL
        if target.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        
        # Domain
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "domain"
        
        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return "ip"
        
        # IPv6
        if ':' in target and re.match(r'^[a-fA-F0-9:]+$', target):
            return "ipv6"
        
        # Phone number
        if re.match(r'^\+?[0-9\s-]{10,}$', target):
            return "phone"
        
        # Bitcoin address
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', target):
            return "bitcoin"
        
        # Ethereum address
        if re.match(r'^0x[a-fA-F0-9]{40}$', target):
            return "ethereum"
        
        # Onion address
        if target.endswith('.onion'):
            return "onion"
        
        # I2P address
        if target.endswith('.i2p'):
            return "i2p"
        
        # Username (simple detection)
        if re.match(r'^[a-zA-Z0-9_]{3,}$', target):
            return "username"
        
        return "unknown"
    
    def get_target(self, target_id: int) -> Optional[Target]:
        """Get a target by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
            row = cursor.fetchone()
            
            if row:
                return Target(
                    id=row['id'],
                    target=row['target'],
                    target_type=row['target_type'],
                    metadata=json.loads(row['metadata']),
                    tags=json.loads(row['tags']),
                    added_at=row['added_at'],
                    updated_at=row['updated_at'],
                    status=row['status']
                )
        return None
    
    def get_target_by_value(self, target: str) -> Optional[Target]:
        """Get a target by its value"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE target = ?", (target,))
            row = cursor.fetchone()
            
            if row:
                return Target(
                    id=row['id'],
                    target=row['target'],
                    target_type=row['target_type'],
                    metadata=json.loads(row['metadata']),
                    tags=json.loads(row['tags']),
                    added_at=row['added_at'],
                    updated_at=row['updated_at'],
                    status=row['status']
                )
        return None
    
    def get_all_targets(self, target_type: Optional[str] = None, 
                        status: Optional[str] = None, 
                        tags: Optional[List[str]] = None) -> List[Target]:
        """Get all targets with optional filters"""
        targets = []
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM targets"
            params = []
            
            conditions = []
            if target_type:
                conditions.append("target_type = ?")
                params.append(target_type)
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY added_at DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                target = Target(
                    id=row['id'],
                    target=row['target'],
                    target_type=row['target_type'],
                    metadata=json.loads(row['metadata']),
                    tags=json.loads(row['tags']),
                    added_at=row['added_at'],
                    updated_at=row['updated_at'],
                    status=row['status']
                )
                
                # Filter by tags if specified
                if tags:
                    target_tags = set(target.tags)
                    if not all(tag in target_tags for tag in tags):
                        continue
                
                targets.append(target)
        
        return targets
    
    def update_target(self, target_id: int, **kwargs) -> bool:
        """Update a target"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Get current target
                cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
                row = cursor.fetchone()
                
                if not row:
                    return False
                
                # Build update query
                updates = []
                params = []
                
                for key, value in kwargs.items():
                    if key == 'metadata' or key == 'tags':
                        value = json.dumps(value)
                    updates.append(f"{key} = ?")
                    params.append(value)
                
                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(target_id)
                
                query = f"UPDATE targets SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, params)
                conn.commit()
                return True
    
    def delete_target(self, target_id: int) -> bool:
        """Delete a target and all its results"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete results first (cascade will handle this, but explicit is better)
                cursor.execute("DELETE FROM results WHERE target_id = ?", (target_id,))
                cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
                conn.commit()
                return cursor.rowcount > 0
    
    # Result CRUD operations
    
    def add_result(self, result: Result) -> Result:
        """Add a new result to the database"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Encrypt sensitive data
                encrypted_data = self._encrypt_data(result.data)
                
                cursor.execute("""
                    INSERT INTO results (
                        target_id, module, module_version, data, status, error, 
                        started_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.target_id,
                    result.module,
                    result.module_version,
                    json.dumps(encrypted_data),
                    result.status,
                    result.error,
                    result.started_at,
                    result.completed_at
                ))
                
                result.id = cursor.lastrowid
                conn.commit()
        
        return result
    
    def get_result(self, result_id: int) -> Optional[Result]:
        """Get a result by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM results WHERE id = ?", (result_id,))
            row = cursor.fetchone()
            
            if row:
                data = json.loads(row['data'])
                decrypted_data = self._decrypt_data(data)
                
                return Result(
                    id=row['id'],
                    target_id=row['target_id'],
                    module=row['module'],
                    module_version=row['module_version'],
                    data=decrypted_data,
                    status=row['status'],
                    error=row['error'],
                    started_at=row['started_at'],
                    completed_at=row['completed_at']
                )
        return None
    
    def get_results_by_target(self, target_id: int, module: Optional[str] = None,
                              status: Optional[str] = None) -> List[Result]:
        """Get all results for a target"""
        results = []
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM results WHERE target_id = ?"
            params = [target_id]
            
            if module:
                query += " AND module = ?"
                params.append(module)
            if status:
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY started_at DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                data = json.loads(row['data'])
                decrypted_data = self._decrypt_data(data)
                
                result = Result(
                    id=row['id'],
                    target_id=row['target_id'],
                    module=row['module'],
                    module_version=row['module_version'],
                    data=decrypted_data,
                    status=row['status'],
                    error=row['error'],
                    started_at=row['started_at'],
                    completed_at=row['completed_at']
                )
                results.append(result)
        
        return results
    
    def get_results_by_module(self, module: str, status: Optional[str] = None) -> List[Result]:
        """Get all results for a module"""
        results = []
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM results WHERE module = ?"
            params = [module]
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY started_at DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                data = json.loads(row['data'])
                decrypted_data = self._decrypt_data(data)
                
                result = Result(
                    id=row['id'],
                    target_id=row['target_id'],
                    module=row['module'],
                    module_version=row['module_version'],
                    data=decrypted_data,
                    status=row['status'],
                    error=row['error'],
                    started_at=row['started_at'],
                    completed_at=row['completed_at']
                )
                results.append(result)
        
        return results
    
    def delete_result(self, result_id: int) -> bool:
        """Delete a result"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM results WHERE id = ?", (result_id,))
                conn.commit()
                return cursor.rowcount > 0
    
    # Module CRUD operations
    
    def add_module(self, module_info: ModuleInfo) -> ModuleInfo:
        """Add or update a module"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if module exists
                cursor.execute("SELECT id FROM modules WHERE name = ?", (module_info.name,))
                existing = cursor.fetchone()
                
                if existing:
                    module_info.id = existing['id']
                    cursor.execute("""
                        UPDATE modules SET 
                            version = ?,
                            author = ?,
                            description = ?,
                            category = ?,
                            target_types = ?,
                            dependencies = ?,
                            config = ?,
                            enabled = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (
                        module_info.version,
                        module_info.author,
                        module_info.description,
                        module_info.category,
                        json.dumps(module_info.target_types),
                        json.dumps(module_info.dependencies),
                        json.dumps(module_info.config),
                        int(module_info.enabled),
                        module_info.id
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO modules (
                            name, version, author, description, category,
                            target_types, dependencies, config, enabled, installed_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """, (
                        module_info.name,
                        module_info.version,
                        module_info.author,
                        module_info.description,
                        module_info.category,
                        json.dumps(module_info.target_types),
                        json.dumps(module_info.dependencies),
                        json.dumps(module_info.config),
                        int(module_info.enabled)
                    ))
                    module_info.id = cursor.lastrowid
                
                conn.commit()
        
        return module_info
    
    def get_module(self, module_name: str) -> Optional[ModuleInfo]:
        """Get a module by name"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM modules WHERE name = ?", (module_name,))
            row = cursor.fetchone()
            
            if row:
                return ModuleInfo(
                    id=row['id'],
                    name=row['name'],
                    version=row['version'],
                    author=row['author'],
                    description=row['description'],
                    category=row['category'],
                    target_types=json.loads(row['target_types']),
                    dependencies=json.loads(row['dependencies']),
                    config=json.loads(row['config']),
                    enabled=bool(row['enabled']),
                    installed_at=row['installed_at'],
                    updated_at=row['updated_at']
                )
        return None
    
    def get_all_modules(self, category: Optional[str] = None, 
                         enabled: Optional[bool] = None) -> List[ModuleInfo]:
        """Get all modules with optional filters"""
        modules = []
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM modules"
            params = []
            
            conditions = []
            if category:
                conditions.append("category = ?")
                params.append(category)
            if enabled is not None:
                conditions.append("enabled = ?")
                params.append(int(enabled))
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY category, name"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                module = ModuleInfo(
                    id=row['id'],
                    name=row['name'],
                    version=row['version'],
                    author=row['author'],
                    description=row['description'],
                    category=row['category'],
                    target_types=json.loads(row['target_types']),
                    dependencies=json.loads(row['dependencies']),
                    config=json.loads(row['config']),
                    enabled=bool(row['enabled']),
                    installed_at=row['installed_at'],
                    updated_at=row['updated_at']
                )
                modules.append(module)
        
        return modules
    
    def delete_module(self, module_name: str) -> bool:
        """Delete a module"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM modules WHERE name = ?", (module_name,))
                conn.commit()
                return cursor.rowcount > 0
    
    # Utility methods
    
    def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search across all data"""
        results = []
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Search targets
            cursor.execute("""
                SELECT 'target' as type, id, target as value, target_type, added_at
                FROM targets 
                WHERE target LIKE ? OR target_type LIKE ? OR tags LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit // 3))
            
            for row in cursor.fetchall():
                results.append({
                    'type': row['type'],
                    'id': row['id'],
                    'value': row['value'],
                    'target_type': row['target_type'],
                    'timestamp': row['added_at']
                })
            
            # Search results
            cursor.execute("""
                SELECT 'result' as type, r.id, t.target as value, r.module, r.status, r.started_at
                FROM results r
                JOIN targets t ON r.target_id = t.id
                WHERE r.module LIKE ? OR r.data LIKE ? OR t.target LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit // 3))
            
            for row in cursor.fetchall():
                results.append({
                    'type': row['type'],
                    'id': row['id'],
                    'value': row['value'],
                    'module': row['module'],
                    'status': row['status'],
                    'timestamp': row['started_at']
                })
            
            # Search modules
            cursor.execute("""
                SELECT 'module' as type, id, name as value, category, description, installed_at
                FROM modules 
                WHERE name LIKE ? OR category LIKE ? OR description LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit // 3))
            
            for row in cursor.fetchall():
                results.append({
                    'type': row['type'],
                    'id': row['id'],
                    'value': row['value'],
                    'category': row['category'],
                    'description': row['description'],
                    'timestamp': row['installed_at']
                })
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        stats = {
            'targets': 0,
            'results': 0,
            'modules': 0,
            'targets_by_type': {},
            'results_by_module': {},
            'results_by_status': {}
        }
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total counts
            cursor.execute("SELECT COUNT(*) FROM targets")
            stats['targets'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM results")
            stats['results'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM modules")
            stats['modules'] = cursor.fetchone()[0]
            
            # Targets by type
            cursor.execute("SELECT target_type, COUNT(*) as count FROM targets GROUP BY target_type")
            for row in cursor.fetchall():
                stats['targets_by_type'][row['target_type']] = row['count']
            
            # Results by module
            cursor.execute("SELECT module, COUNT(*) as count FROM results GROUP BY module")
            for row in cursor.fetchall():
                stats['results_by_module'][row['module']] = row['count']
            
            # Results by status
            cursor.execute("SELECT status, COUNT(*) as count FROM results GROUP BY status")
            for row in cursor.fetchall():
                stats['results_by_status'][row['status']] = row['count']
        
        return stats
    
    def backup(self, backup_path: Optional[str] = None) -> str:
        """Create a backup of the database"""
        import shutil
        from datetime import datetime
        
        backup_dir = Path("~/.shadowscope/backups").expanduser()
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = str(backup_dir / f"shadowscope_backup_{timestamp}.db")
        
        shutil.copy2(str(self._db_path), backup_path)
        
        # Encrypt backup if encryption is enabled
        if self.config.storage.encryption.get('enabled', True):
            self._encrypt_backup(backup_path)
        
        return backup_path
    
    def _encrypt_backup(self, backup_path: str):
        """Encrypt a backup file"""
        if not self.encryption._fernet:
            return
        
        backup_path_obj = Path(backup_path)
        encrypted_path = backup_path_obj.with_suffix('.db.enc')
        
        with open(backup_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encryption._fernet.encrypt(data)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        
        # Remove original
        backup_path_obj.unlink()
    
    def export_json(self, output_path: str, 
                   targets: bool = True, 
                   results: bool = True, 
                   modules: bool = True):
        """Export data to JSON"""
        data = {}
        
        if targets:
            data['targets'] = [t.to_dict() for t in self.get_all_targets()]
        
        if results:
            data['results'] = []
            all_results = self.get_results_by_module("")
            data['results'] = [r.to_dict() for r in all_results]
        
        if modules:
            data['modules'] = [m.to_dict() for m in self.get_all_modules()]
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return output_path
    
    def import_json(self, input_path: str):
        """Import data from JSON"""
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        with self._lock:
            for target_data in data.get('targets', []):
                target = Target(**target_data)
                self.add_target(target)
            
            for module_data in data.get('modules', []):
                module = ModuleInfo(**module_data)
                self.add_module(module)
            
            # Results need to be associated with existing targets
            target_map = {t.target: t.id for t in self.get_all_targets()}
            for result_data in data.get('results', []):
                if result_data['target_id'] in target_map.values():
                    result = Result(**result_data)
                    self.add_result(result)


# Initialize storage
storage = Storage()
