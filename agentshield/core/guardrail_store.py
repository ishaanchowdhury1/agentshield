import sqlite3
from pathlib import Path
from datetime import datetime, timezone


DB_PATH = Path(__file__).resolve().parents[2] / "agentshield.db"


class GuardrailStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._initialize()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS guardrail_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL UNIQUE,
                    rule_text TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    triggered_by_attack TEXT,
                    accepted INTEGER NOT NULL DEFAULT 0
                )
            """)

    def save_version(
        self,
        rule_text: str,
        triggered_by_attack: str = None,
        accepted: bool = False,
    ):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM guardrail_versions"
            ).fetchone()

            version = row[0] + 1

            conn.execute(
                """
                INSERT INTO guardrail_versions
                (version, rule_text, created_at,
                 triggered_by_attack, accepted)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    version,
                    rule_text,
                    datetime.now(timezone.utc).isoformat(),
                    triggered_by_attack,
                    int(accepted),
                ),
            )

        return version

    def get_latest(self, accepted_only=True):
        query = """
            SELECT version, rule_text, created_at,
                   triggered_by_attack, accepted
            FROM guardrail_versions
        """

        if accepted_only:
            query += " WHERE accepted = 1"

        query += " ORDER BY version DESC LIMIT 1"

        with self._connect() as conn:
            row = conn.execute(query).fetchone()

        if row is None:
            return None

        return {
            "version": row[0],
            "rule_text": row[1],
            "created_at": row[2],
            "triggered_by_attack": row[3],
            "accepted": bool(row[4]),
        }

    def get_history(self):
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT version, rule_text, created_at,
                       triggered_by_attack, accepted
                FROM guardrail_versions
                ORDER BY version ASC
            """).fetchall()

        return [
            {
                "version": row[0],
                "rule_text": row[1],
                "created_at": row[2],
                "triggered_by_attack": row[3],
                "accepted": bool(row[4]),
            }
            for row in rows
        ]

    def get_diff(self, old_version: int, new_version: int):
        with self._connect() as conn:
            old = conn.execute(
                "SELECT rule_text FROM guardrail_versions WHERE version = ?",
                (old_version,),
            ).fetchone()

            new = conn.execute(
                "SELECT rule_text FROM guardrail_versions WHERE version = ?",
                (new_version,),
            ).fetchone()

        if old is None or new is None:
            raise ValueError("One or both guardrail versions do not exist.")

        import difflib

        return list(
            difflib.unified_diff(
                old[0].splitlines(),
                new[0].splitlines(),
                fromfile=f"guardrail_v{old_version}",
                tofile=f"guardrail_v{new_version}",
                lineterm="",
            )
        )
