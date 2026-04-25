import json
import os
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_client = None

def get_redis():
    global _client
    if _client is None:
        try:
            _client = redis.from_url(REDIS_URL, decode_responses=True)
            _client.ping()
        except Exception:
            _client = None
    return _client


class JobStore:
    """Redis-backed job store with dict fallback."""

    def __init__(self):
        self._fallback: dict = {}

    def _r(self):
        return get_redis()

    def __setitem__(self, key: str, value: dict):
        r = self._r()
        if r:
            r.set(f"job:{key}", json.dumps(value, default=str), ex=86400)
        else:
            self._fallback[key] = value

    def __getitem__(self, key: str) -> dict:
        r = self._r()
        if r:
            raw = r.get(f"job:{key}")
            if raw is None:
                raise KeyError(key)
            return json.loads(raw)
        return self._fallback[key]

    def __contains__(self, key: str) -> bool:
        r = self._r()
        if r:
            return bool(r.exists(f"job:{key}"))
        return key in self._fallback

    def __delitem__(self, key: str):
        r = self._r()
        if r:
            r.delete(f"job:{key}")
        else:
            del self._fallback[key]

    def values(self):
        r = self._r()
        if r:
            keys = r.keys("job:*")
            return [json.loads(r.get(k)) for k in keys if r.get(k)]
        return self._fallback.values()

    def clear(self):
        r = self._r()
        if r:
            for k in r.keys("job:*"):
                r.delete(k)
        else:
            self._fallback.clear()

    def setdefault(self, key: str, default: dict) -> dict:
        if key not in self:
            self[key] = default
        return self[key]

    def update_job(self, key: str, updates: dict):
        """Atomic read-modify-write for job updates."""
        try:
            current = self[key]
        except KeyError:
            current = {}
        current.update(updates)
        self[key] = current