"""Persistent SQLite analysis cache and whole-file hashing.

The cache is keyed by (path, parser_version) with a content-hash fallback so an
identical artifact that moved to a new path can still be reused. Bump
``V7_PARSER_VERSION`` (in postmortem.config) whenever the record schema or analysis
changes, so stale rows are never reused.
"""

import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from postmortem.config import V7_PARSER_VERSION
from postmortem.models import EmailRecord


class SQLiteRecordCache:
    """Persistent cache keyed by content hash + parser version.

    A fast path uses path/size/mtime_ns to avoid hashing unchanged files. When
    metadata changes, the file is hashed and an identical prior artifact can
    still be reused even if it moved to a different path.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(
            str(self.path),
            timeout=30,
            check_same_thread=False,
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("PRAGMA cache_size=-65536")
        self.conn.execute("PRAGMA mmap_size=268435456")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS records (
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                file_sha256 TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                record_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(path, parser_version)
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_records_hash
            ON records(file_sha256, parser_version)
        """)
        self.conn.commit()

    def fast_get(self, path: Path):
        st = path.stat()
        row = self.conn.execute(
            """
            SELECT file_sha256, record_json
            FROM records
            WHERE path=? AND size=? AND mtime_ns=? AND parser_version=?
            """,
            (str(path), st.st_size, st.st_mtime_ns, V7_PARSER_VERSION),
        ).fetchone()
        if not row:
            return None
        return row[0], EmailRecord(**json.loads(row[1]))

    def get_by_hash(self, file_sha256: str):
        row = self.conn.execute(
            """
            SELECT record_json
            FROM records
            WHERE file_sha256=? AND parser_version=?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (file_sha256, V7_PARSER_VERSION),
        ).fetchone()
        if not row:
            return None
        return EmailRecord(**json.loads(row[0]))

    def put(self, path: Path, file_sha256: str, record: EmailRecord):
        st = path.stat()
        self.conn.execute(
            """
            INSERT INTO records
                (path,size,mtime_ns,file_sha256,parser_version,record_json)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(path,parser_version) DO UPDATE SET
                size=excluded.size,
                mtime_ns=excluded.mtime_ns,
                file_sha256=excluded.file_sha256,
                record_json=excluded.record_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                str(path),
                st.st_size,
                st.st_mtime_ns,
                file_sha256,
                V7_PARSER_VERSION,
                json.dumps(asdict(record), ensure_ascii=False),
            ),
        )
        self.conn.commit()

    def put_batch(self, rows):
        """Persist many records in one transaction."""
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO records
                (path,size,mtime_ns,file_sha256,parser_version,record_json)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(path,parser_version) DO UPDATE SET
                size=excluded.size,
                mtime_ns=excluded.mtime_ns,
                file_sha256=excluded.file_sha256,
                record_json=excluded.record_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            rows,
        )
        self.conn.commit()

    def get_by_hash_batch(self, hashes):
        if not hashes:
            return {}
        result = {}
        # SQLite parameter limits vary; keep chunks comfortably below them.
        for offset in range(0, len(hashes), 500):
            chunk = hashes[offset:offset + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = self.conn.execute(
                f"""
                SELECT file_sha256, record_json
                FROM records
                WHERE parser_version=?
                  AND file_sha256 IN ({placeholders})
                """,
                [V7_PARSER_VERSION, *chunk],
            ).fetchall()
            for file_hash, record_json in rows:
                result[file_hash] = EmailRecord(**json.loads(record_json))
        return result

    def close(self):
        self.conn.close()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
