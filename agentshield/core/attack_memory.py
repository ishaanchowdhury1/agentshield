import sqlite3
import uuid
from pathlib import Path
from datetime import datetime, timezone


DB_PATH = Path(__file__).resolve().parents[2] / "agentshield.db"


class AttackMemory:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self._initialize()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_memory (
                    attack_id TEXT PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    round_number INTEGER NOT NULL,
                    attack_text TEXT NOT NULL,
                    category TEXT,
                    outcome TEXT NOT NULL,
                    severity TEXT,
                    feedback TEXT,
                    guardrail_version INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (guardrail_version)
                        REFERENCES guardrail_versions(version)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_attack_memory_assessment
                ON attack_memory(assessment_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_attack_memory_version
                ON attack_memory(guardrail_version)
            """)

    def record(
        self,
        assessment_id: str,
        round_number: int,
        attack_text: str,
        outcome: dict,
        guardrail_version: int,
        category: str = None,
    ):
        if not assessment_id:
            raise ValueError("assessment_id is required.")

        if round_number < 1:
            raise ValueError("round_number must be >= 1.")

        if guardrail_version < 1:
            raise ValueError("guardrail_version must be >= 1.")

        result = outcome.get("result")

        if result not in {"SAFE", "VULNERABLE"}:
            raise ValueError("Invalid attack outcome.")

        attack_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO attack_memory (
                    attack_id,
                    assessment_id,
                    round_number,
                    attack_text,
                    category,
                    outcome,
                    severity,
                    feedback,
                    guardrail_version,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack_id,
                    assessment_id,
                    round_number,
                    attack_text,
                    category,
                    result,
                    outcome.get("severity"),
                    outcome.get("reason"),
                    guardrail_version,
                    created_at,
                ),
            )

        return attack_id

    def get_assessment(self, assessment_id: str):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            rows = conn.execute(
                """
                SELECT *
                FROM attack_memory
                WHERE assessment_id = ?
                ORDER BY round_number, created_at
                """,
                (assessment_id,),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_previous_attacks(self, assessment_id: str):
        records = self.get_assessment(assessment_id)

        return [
            record["attack_text"]
            for record in records
        ]

    def get_bypass_rates(self, assessment_id: str):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    round_number,
                    guardrail_version,
                    COUNT(*) AS total,
                    SUM(
                        CASE
                            WHEN outcome = 'VULNERABLE'
                            THEN 1 ELSE 0
                        END
                    ) AS vulnerable
                FROM attack_memory
                WHERE assessment_id = ?
                GROUP BY round_number, guardrail_version
                ORDER BY round_number, guardrail_version
                """,
                (assessment_id,),
            ).fetchall()

        return [
            {
                "round_number": row[0],
                "guardrail_version": row[1],
                "total": row[2],
                "vulnerable": row[3],
                "bypass_rate": (
                    row[3] / row[2] * 100
                    if row[2]
                    else 0.0
                ),
            }
            for row in rows
        ]
