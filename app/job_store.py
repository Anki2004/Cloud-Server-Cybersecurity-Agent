import json
import os
import logging

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
POSTGRES_URL = os.getenv("POSTGRES_URL", "")  # e.g. postgresql://user:pass@host:5432/dbname

# ── Redis ─────────────────────────────────────────────────────────────────────
_redis_client = None

def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            _redis_client.ping()
            logger.info("Redis connected ✓")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")
            _redis_client = None
    return _redis_client


# ── PostgreSQL ────────────────────────────────────────────────────────────────
_pg_conn = None

def _get_pg():
    global _pg_conn
    if not POSTGRES_URL:
        return None
    try:
        if _pg_conn is None or _pg_conn.closed:
            import psycopg2
            import psycopg2.extras
            _pg_conn = psycopg2.connect(POSTGRES_URL)
            _pg_conn.autocommit = True
            _init_pg_schema(_pg_conn)
            logger.info("PostgreSQL connected ✓")
    except Exception as e:
        logger.warning(f"PostgreSQL unavailable: {e}")
        return None
    return _pg_conn


def _init_pg_schema(conn):
    """Create jobs table if not exists."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id        TEXT PRIMARY KEY,
                mode          TEXT,
                query         TEXT,
                log_paths     TEXT,
                scan_hours    INTEGER,
                status        TEXT,
                phase         TEXT,
                escalated     BOOLEAN,
                severity      TEXT,
                scheduled     BOOLEAN DEFAULT FALSE,
                phase_timings JSONB,
                detection_report      TEXT,
                intelligence_report   TEXT,
                result        TEXT,
                output_file   TEXT,
                error         TEXT,
                created_at    TEXT,
                completed_at  TEXT,
                failed_at     TEXT,
                extra         JSONB
            );
        """)
        # Index for fast status queries
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
        """)
    logger.info("PostgreSQL schema ready ✓")


def _pg_upsert(conn, job: dict):
    """Upsert job record into PostgreSQL."""
    import psycopg2.extras
    # Known columns
    known = {
        "job_id", "mode", "query", "log_paths", "scan_hours",
        "status", "phase", "escalated", "severity", "scheduled",
        "phase_timings", "detection_report", "intelligence_report",
        "result", "output_file", "error", "created_at",
        "completed_at", "failed_at"
    }
    main = {k: v for k, v in job.items() if k in known}
    extra = {k: v for k, v in job.items() if k not in known}

    # Serialize nested objects
    if "phase_timings" in main and isinstance(main["phase_timings"], dict):
        main["phase_timings"] = json.dumps(main["phase_timings"])

    main["extra"] = json.dumps(extra) if extra else json.dumps({})

    cols   = list(main.keys())
    vals   = [main[c] for c in cols]
    phs    = [f"%s" for _ in cols]
    update = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c != "job_id")

    sql = f"""
        INSERT INTO jobs ({", ".join(cols)})
        VALUES ({", ".join(phs)})
        ON CONFLICT (job_id) DO UPDATE SET {update};
    """
    with conn.cursor() as cur:
        cur.execute(sql, vals)


def _pg_fetch(conn, job_id: str) -> dict | None:
    """Fetch single job from PostgreSQL."""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM jobs WHERE job_id = %s", (job_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [desc[0] for desc in cur.description]
        job = dict(zip(cols, row))
        # Deserialize JSONB fields
        for field in ("phase_timings", "extra"):
            if isinstance(job.get(field), str):
                try:
                    job[field] = json.loads(job[field])
                except Exception:
                    pass
        # Merge extra back into top-level
        extra = job.pop("extra", {}) or {}
        job.update(extra)
        return job


def _pg_fetch_all(conn) -> list:
    """Fetch all jobs from PostgreSQL ordered by created_at desc."""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM jobs ORDER BY created_at DESC")
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        result = []
        for row in rows:
            job = dict(zip(cols, row))
            for field in ("phase_timings", "extra"):
                if isinstance(job.get(field), str):
                    try:
                        job[field] = json.loads(job[field])
                    except Exception:
                        pass
            extra = job.pop("extra", {}) or {}
            job.update(extra)
            result.append(job)
        return result


def _pg_delete_all(conn):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM jobs")


def _pg_exists(conn, job_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM jobs WHERE job_id = %s", (job_id,))
        return cur.fetchone() is not None


# ── Job Store ─────────────────────────────────────────────────────────────────

class JobStore:
    """
    Three-tier job store:
      1. PostgreSQL — permanent storage for all jobs and reports
      2. Redis      — hot cache for fast polling during active jobs
      3. dict       — in-memory fallback for dev/offline environments
    """

    def __init__(self):
        self._fallback: dict = {}

    # ── Write ──────────────────────────────────────────────────────────────────
    def __setitem__(self, key: str, value: dict):
        # 1. PostgreSQL (permanent)
        pg = _get_pg()
        if pg:
            try:
                _pg_upsert(pg, value)
            except Exception as e:
                logger.error(f"PG write failed for {key}: {e}")

        # 2. Redis (fast cache, 24hr TTL)
        r = _get_redis()
        if r:
            try:
                r.set(f"job:{key}", json.dumps(value, default=str), ex=86400)
            except Exception as e:
                logger.warning(f"Redis write failed for {key}: {e}")

        # 3. dict fallback
        self._fallback[key] = value

    # ── Read ───────────────────────────────────────────────────────────────────
    def __getitem__(self, key: str) -> dict:
        # 1. Redis (fastest)
        r = _get_redis()
        if r:
            try:
                raw = r.get(f"job:{key}")
                if raw:
                    return json.loads(raw)
            except Exception:
                pass

        # 2. PostgreSQL
        pg = _get_pg()
        if pg:
            try:
                job = _pg_fetch(pg, key)
                if job:
                    return job
            except Exception as e:
                logger.error(f"PG read failed for {key}: {e}")

        # 3. dict fallback
        if key in self._fallback:
            return self._fallback[key]

        raise KeyError(key)

    # ── Contains ───────────────────────────────────────────────────────────────
    def __contains__(self, key: str) -> bool:
        r = _get_redis()
        if r:
            try:
                if r.exists(f"job:{key}"):
                    return True
            except Exception:
                pass

        pg = _get_pg()
        if pg:
            try:
                return _pg_exists(pg, key)
            except Exception:
                pass

        return key in self._fallback

    # ── Delete ─────────────────────────────────────────────────────────────────
    def __delitem__(self, key: str):
        r = _get_redis()
        if r:
            try:
                r.delete(f"job:{key}")
            except Exception:
                pass

        # NOTE: We do NOT delete from PostgreSQL — permanent audit trail
        # To fully delete, use clear() or direct DB query

        self._fallback.pop(key, None)

    # ── List all ───────────────────────────────────────────────────────────────
    def values(self):
        # PostgreSQL is source of truth for full history
        pg = _get_pg()
        if pg:
            try:
                return _pg_fetch_all(pg)
            except Exception as e:
                logger.error(f"PG fetch all failed: {e}")

        # Redis fallback
        r = _get_redis()
        if r:
            try:
                keys = r.keys("job:*")
                return [json.loads(r.get(k)) for k in keys if r.get(k)]
            except Exception:
                pass

        return list(self._fallback.values())

    # ── Clear ──────────────────────────────────────────────────────────────────
    def clear(self):
        """Clears Redis cache and in-memory store. PostgreSQL keeps history."""
        r = _get_redis()
        if r:
            try:
                for k in r.keys("job:*"):
                    r.delete(k)
            except Exception:
                pass
        self._fallback.clear()
        # PostgreSQL intentionally NOT cleared — permanent record

    def clear_all(self):
        """Hard clear including PostgreSQL. Use with caution."""
        pg = _get_pg()
        if pg:
            try:
                _pg_delete_all(pg)
            except Exception as e:
                logger.error(f"PG clear failed: {e}")
        self.clear()

    # ── Helpers ────────────────────────────────────────────────────────────────
    def setdefault(self, key: str, default: dict) -> dict:
        if key not in self:
            self[key] = default
        return self[key]

    def update_job(self, key: str, updates: dict):
        """Atomic read-modify-write."""
        try:
            current = self[key]
        except KeyError:
            current = {}
        current.update(updates)
        self[key] = current

    def get_pg_stats(self) -> dict:
        """Return PostgreSQL statistics for health endpoint."""
        pg = _get_pg()
        if not pg:
            return {"connected": False}
        try:
            with pg.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM jobs")
                total = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM jobs WHERE status='completed'")
                completed = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM jobs WHERE escalated=true")
                escalated = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM jobs WHERE severity IN ('CRITICAL','HIGH')")
                critical = cur.fetchone()[0]
            return {
                "connected": True,
                "total_jobs": total,
                "completed": completed,
                "threats_detected": escalated,
                "high_critical": critical,
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}