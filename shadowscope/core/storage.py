"""
Storage Layer for SHADOWSCOPE
Handles encrypted SQLite storage for all investigation data.
"""

import csv
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from rich.console import Console

console = Console()


@dataclass
class Target:
    """Represents an investigation target"""
    id: int | None = None
    target: str = ""
    target_type: str = "unknown"  # domain, ip, email, phone, url, etc.
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"  # pending, processing, completed, failed

    def to_dict(self) -> dict[str, Any]:
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
    id: int | None = None
    target_id: int = 0
    module: str = ""
    module_version: str = "1.0"
    data: dict[str, Any] = field(default_factory=dict)
    status: str = "success"  # success, failed, partial
    error: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
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
    id: int | None = None
    name: str = ""
    version: str = "1.0"
    author: str = ""
    description: str = ""
    category: str = ""
    target_types: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    installed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
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

    def __init__(self, encryption_key: bytes | None = None):
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
        except Exception:
            return value

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a value"""
        if not self._fernet:
            return encrypted_value
        try:
            decrypted = self._fernet.decrypt(encrypted_value.encode())
            return decrypted.decode()
        except Exception:
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
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        """Initialize database and create tables"""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")

            self._create_tables(conn)

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection"""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _create_tables(self, conn: sqlite3.Connection):
        """Create all database tables"""
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

        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(target_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_added ON targets(added_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_module ON results(module)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON results(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_started ON results(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_modules_category ON modules(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_modules_enabled ON modules(enabled)")

    def _encrypt_data(self, data: dict[str, Any]) -> dict[str, Any]:
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

    def _decrypt_data(self, data: dict[str, Any]) -> dict[str, Any]:
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

    def add_target(self, target: str | Target, target_type: str | None = None,
                   tags: list[str] | None = None, metadata: dict[str, Any] | None = None) -> Target:
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

                cursor.execute("SELECT id FROM targets WHERE target = ?", (target_obj.target,))
                existing = cursor.fetchone()

                if existing:
                    target_obj.id = existing['id']
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

        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "email"
        if target.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "domain"
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return "ip"
        if ':' in target and re.match(r'^[a-fA-F0-9:]+$', target):
            return "ipv6"
        if re.match(r'^\+?[0-9\s-]{10,}$', target):
            return "phone"
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', target):
            return "bitcoin"
        if re.match(r'^0x[a-fA-F0-9]{40}$', target):
            return "ethereum"
        if target.endswith('.onion'):
            return "onion"
        if target.endswith('.i2p'):
            return "i2p"
        if re.match(r'^[a-zA-Z0-9_]{3,}$', target):
            return "username"

        return "unknown"

    def get_target(self, target_id: int) -> Target | None:
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

    def get_target_by_value(self, target: str) -> Target | None:
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

    def get_all_targets(self, target_type: str | None = None,
                        status: str | None = None,
                        tags: list[str] | None = None) -> list[Target]:
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

                cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
                row = cursor.fetchone()

                if not row:
                    return False

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

    def get_result(self, result_id: int) -> Result | None:
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

    def get_results_by_target(self, target_id: int, module: str | None = None,
                              status: str | None = None) -> list[Result]:
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

    def get_results_by_module(self, module: str, status: str | None = None) -> list[Result]:
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

    def add_module(self, module_info: Any) -> Any:
        """Add or update a module"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT id FROM modules WHERE name = ?", (module_info.name,))
                existing = cursor.fetchone()

                config_data = getattr(module_info, "config", getattr(module_info, "config_schema", {}))

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
                        json.dumps(config_data),
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
                        json.dumps(config_data),
                        int(module_info.enabled)
                    ))
                    module_info.id = cursor.lastrowid

                conn.commit()

        return module_info

    def get_module(self, module_name: str) -> ModuleInfo | None:
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

    def get_all_modules(self, category: str | None = None,
                         enabled: bool | None = None) -> list[ModuleInfo]:
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

    def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        """Search across all data"""
        results = []

        with self._get_connection() as conn:
            cursor = conn.cursor()

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

    def get_stats(self) -> dict[str, Any]:
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

            cursor.execute("SELECT COUNT(*) FROM targets")
            stats['targets'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM results")
            stats['results'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM modules")
            stats['modules'] = cursor.fetchone()[0]

            cursor.execute("SELECT target_type, COUNT(*) as count FROM targets GROUP BY target_type")
            for row in cursor.fetchall():
                stats['targets_by_type'][row['target_type']] = row['count']

            cursor.execute("SELECT module, COUNT(*) as count FROM results GROUP BY module")
            for row in cursor.fetchall():
                stats['results_by_module'][row['module']] = row['count']

            cursor.execute("SELECT status, COUNT(*) as count FROM results GROUP BY status")
            for row in cursor.fetchall():
                stats['results_by_status'][row['status']] = row['count']

        return stats

    def backup(self, backup_path: str | None = None) -> str:
        """Create a backup of the database"""

        backup_dir = Path("~/.shadowscope/backups").expanduser()
        backup_dir.mkdir(parents=True, exist_ok=True)

        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = str(backup_dir / f"shadowscope_backup_{timestamp}.db")

        source = self._get_connection()
        destination = sqlite3.connect(backup_path)
        try:
            with destination:
                source.backup(destination)
        finally:
            destination.close()
            source.close()

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

    def export_csv(self, output_path: str) -> str:
        """Export targets and execution results to CSV format."""
        all_targets = {t.id: t for t in self.get_all_targets()}
        all_results = self.get_results_by_module("")

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Target ID", "Target Value", "Target Type", "Module",
                "Status", "Started At", "Completed At", "Summary / Details", "Error"
            ])

            for r in all_results:
                t = all_targets.get(r.target_id)
                target_val = t.target if t else str(r.target_id)
                target_type = t.target_type if t else "unknown"
                summary = r.data.get("summary", json.dumps(r.data))

                writer.writerow([
                    r.target_id, target_val, target_type, r.module,
                    r.status, r.started_at, r.completed_at, summary, r.error or ""
                ])

        return output_path

    def export_html(self, output_path: str) -> str:
        """Export executive summary and execution results to styled HTML report."""
        stats = self.get_stats()
        all_targets = {t.id: t for t in self.get_all_targets()}
        all_results = self.get_results_by_module("")

        rows_html = ""
        for r in all_results:
            t = all_targets.get(r.target_id)
            target_val = t.target if t else f"Target #{r.target_id}"
            target_type = t.target_type if t else "unknown"
            summary = r.data.get("summary", json.dumps(r.data, indent=1))

            status_badge = f"<span style='color:green; font-weight:bold;'>{r.status}</span>" if r.status == "success" else f"<span style='color:red;'>{r.status}</span>"

            rows_html += f"""
            <tr>
                <td>{r.id}</td>
                <td><strong>{target_val}</strong> ({target_type})</td>
                <td><code>{r.module}</code></td>
                <td>{status_badge}</td>
                <td>{r.started_at[:19]}</td>
                <td><pre style='white-space: pre-wrap; margin:0;'>{summary}</pre></td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SHADOWSCOPE Executive Intelligence Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 30px; line-height: 1.5; }}
        h1, h2 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 8px; }}
        .stats-grid {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background-color: #1e293b; border-radius: 8px; padding: 15px 25px; min-width: 150px; text-align: center; border: 1px solid #334155; }}
        .stat-num {{ font-size: 2em; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background-color: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.85em; }}
        tr:hover {{ background-color: #334155; }}
        code {{ background-color: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
    </style>
</head>
<body>
    <h1>SHADOWSCOPE OSINT Intelligence Report</h1>
    <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-num">{stats['targets']}</div>
            <div>Total Targets</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats['results']}</div>
            <div>Executed Results</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">{stats['modules']}</div>
            <div>Registered Modules</div>
        </div>
    </div>

    <h2>Execution Results Audit Log</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Module</th>
                <th>Status</th>
                <th>Timestamp</th>
                <th>Result Summary</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else "<tr><td colspan='6'>No result records found in database.</td></tr>"}
        </tbody>
    </table>
</body>
</html>
"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def import_json(self, input_path: str):
        """Import data from JSON"""
        with open(input_path) as f:
            data = json.load(f)

        with self._lock:
            for target_data in data.get('targets', []):
                target = Target(**target_data)
                self.add_target(target)

            for module_data in data.get('modules', []):
                module = ModuleInfo(**module_data)
                self.add_module(module)

            target_map = {t.target: t.id for t in self.get_all_targets()}
            for result_data in data.get('results', []):
                if result_data['target_id'] in target_map.values():
                    result = Result(**result_data)
                    self.add_result(result)


# Initialize storage
storage = Storage()
