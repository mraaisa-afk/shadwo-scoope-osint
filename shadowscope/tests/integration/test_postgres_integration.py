"""
Integration tests for the PostgreSQL service used by the CI test job.

The framework's storage layer currently ships a SQLite implementation, but the
CI ``test`` job provisions a ``postgres:15`` container and exports POSTGRES_DSN
for the PostgreSQL backend that ``StorageConfig.backend`` advertises. These
tests verify that the service is really up, reachable with the configured DSN
and usable for real transactional work, so a broken service definition or a
bad DSN fails CI instead of silently degrading to SQLite.

They skip cleanly when no PostgreSQL server is reachable (e.g. local runs).
"""

import json
import uuid
from urllib.parse import urlparse

import pytest

from .conftest import postgres_dsn, postgres_is_available


@pytest.fixture
def table(postgres_connection):
    """A throwaway table that is always dropped again."""
    name = f"shadowscope_itest_{uuid.uuid4().hex[:12]}"
    with postgres_connection.cursor() as cursor:
        cursor.execute(
            f"CREATE TABLE {name} ("
            "id SERIAL PRIMARY KEY, "
            "target TEXT NOT NULL, "
            "payload JSONB NOT NULL DEFAULT '{}'::jsonb)"
        )
    postgres_connection.commit()

    try:
        yield name
    finally:
        postgres_connection.rollback()
        with postgres_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {name}")
        postgres_connection.commit()


class TestServiceAvailability:
    def test_configured_dsn_connects_as_expected_identity(self, postgres_connection):
        parameters = postgres_connection.get_dsn_parameters()
        parsed = urlparse(postgres_dsn())

        assert parameters["host"], "POSTGRES_DSN is missing a host"
        assert parameters["dbname"] == parsed.path.lstrip("/")
        assert parameters["user"] == parsed.username
        if parsed.port is not None:
            assert parameters["port"] == str(parsed.port)

    def test_server_reports_postgresql_version(self, postgres_connection):
        with postgres_connection.cursor() as cursor:
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]

        assert "PostgreSQL" in version

    def test_expected_test_database_exists(self, postgres_connection):
        with postgres_connection.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            database = cursor.fetchone()[0]

        assert database == "shadowscope_test", (
            "CI provisions POSTGRES_DB=shadowscope_test; the DSN points at a different database"
        )

    def test_helper_skips_gracefully_for_unreachable_dsn(self):
        """The availability probe must return False rather than raising."""
        assert postgres_is_available("postgresql://nobody:nobody@127.0.0.1:1/nope") is False


class TestTransactionalBehaviour:
    def test_insert_select_update_delete(self, postgres_connection, table):
        with postgres_connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {table} (target, payload) VALUES (%s, %s) RETURNING id",
                ("scope.example", '{"stage": "initial"}'),
            )
            row_id = cursor.fetchone()[0]
        postgres_connection.commit()

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"SELECT target, payload FROM {table} WHERE id = %s", (row_id,))
            target, payload = cursor.fetchone()
        assert target == "scope.example"
        assert payload == {"stage": "initial"}

        with postgres_connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {table} SET payload = %s WHERE id = %s",
                ('{"stage": "updated"}', row_id),
            )
            assert cursor.rowcount == 1
        postgres_connection.commit()

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"SELECT payload FROM {table} WHERE id = %s", (row_id,))
            assert cursor.fetchone()[0] == {"stage": "updated"}

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"DELETE FROM {table} WHERE id = %s", (row_id,))
            assert cursor.rowcount == 1
        postgres_connection.commit()

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            assert cursor.fetchone()[0] == 0

    def test_rollback_discards_writes(self, postgres_connection, table):
        with postgres_connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO {table} (target) VALUES (%s)", ("discarded.example",))
        postgres_connection.rollback()

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            assert cursor.fetchone()[0] == 0

    def test_constraint_violation_is_enforced(self, postgres_connection, table):
        with postgres_connection.cursor() as cursor:
            with pytest.raises(Exception):
                cursor.execute(f"INSERT INTO {table} (target) VALUES (NULL)")
        postgres_connection.rollback()

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            assert cursor.fetchone()[0] == 0

    def test_jsonb_round_trip_of_module_shaped_payload(self, postgres_connection, table):
        payload = {"records": ["203.0.113.10"], "success": True, "nested": {"depth": 2}}
        with postgres_connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO {table} (target, payload) VALUES (%s, %s) RETURNING payload",
                ("json.example", json.dumps(payload)),
            )
            stored = cursor.fetchone()[0]
        postgres_connection.commit()

        assert stored == payload

    def test_independent_connections_see_committed_rows(self, postgres_connection, table):
        import psycopg2

        with postgres_connection.cursor() as cursor:
            cursor.execute(f"INSERT INTO {table} (target) VALUES (%s)", ("visible.example",))
        postgres_connection.commit()

        second = psycopg2.connect(postgres_dsn(), connect_timeout=3)
        try:
            with second.cursor() as cursor:
                cursor.execute(f"SELECT target FROM {table}")
                assert cursor.fetchone()[0] == "visible.example"
        finally:
            second.close()
