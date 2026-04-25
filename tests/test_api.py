import sys
import types
import unittest

# ── Stub heavy deps ───────────────────────────────────────────────────────────
def make_mod(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

# APScheduler stubs
aps         = make_mod("apscheduler")
aps_sched   = make_mod("apscheduler.schedulers")
aps_bg      = make_mod("apscheduler.schedulers.background")
aps_trig    = make_mod("apscheduler.triggers")
aps_int     = make_mod("apscheduler.triggers.interval")

class _FakeScheduler:
    running = True
    def add_job(self, *a, **k): pass
    def start(self): pass
    def shutdown(self): pass
    def pause(self): pass
    def resume(self): pass
    def get_jobs(self): return []

class _FakeTrigger:
    def __init__(self, **k): pass

aps_bg.BackgroundScheduler = _FakeScheduler
aps_int.IntervalTrigger    = _FakeTrigger

# CrewAI stubs
crewai      = make_mod("crewai")
make_mod("langchain_groq")
lgr = make_mod("langchain_groq")
import langchain_groq
langchain_groq.ChatGroq = type("ChatGroq", (), {
    "__init__":lambda s, **k:None
})
# lgr.ChatGroq = type("ChatGroq", (), {"__init__.py":lambda s, **k:None})
import crewai
crewai.Agent = type("Agent", (), {"__init__":lambda s, **k:None})
crewai.Crew    = type("Crew",    (), {"__init__": lambda s, **k: None, "kickoff": lambda s: ""})
crewai.Process = type("Process", (), {"sequential": "sequential"})
crewai.Task    = type("Task",    (), {"__init__": lambda s, **k: None})

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class HealthEndpointTests(unittest.TestCase):
    def test_health_returns_ok(self):
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")
        self.assertIn("timestamp", r.json())
        self.assertIn("scheduler", r.json())

    def test_root_returns_service_info(self):
        r = client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("endpoints", r.json())


class JobEndpointTests(unittest.TestCase):
    def test_run_detect_queues_job(self):
        r = client.post("/run", json={"mode": "detect"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("job_id", data)
        self.assertEqual(data["status"], "queued")
        self.assertEqual(data["mode"], "detect")

    def test_run_research_queues_job(self):
        r = client.post("/run", json={"mode": "research", "query": "ransomware 2025"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["mode"], "research")

    def test_get_results_returns_job(self):
        r = client.post("/run", json={"mode": "detect"})
        job_id = r.json()["job_id"]
        r2 = client.get(f"/results/{job_id}")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["job_id"], job_id)

    def test_get_results_404_unknown_job(self):
        r = client.get("/results/nonexistent-job-id")
        self.assertEqual(r.status_code, 404)

    def test_list_jobs(self):
        r = client.get("/jobs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("total", r.json())
        self.assertIn("jobs", r.json())

    def test_clear_jobs(self):
        client.post("/run", json={"mode": "detect"})
        r = client.delete("/jobs")
        self.assertEqual(r.status_code, 200)
        r2 = client.get("/jobs")
        self.assertEqual(r2.json()["total"], 0)

    def test_scheduler_endpoint(self):
        r = client.get("/scheduler")
        self.assertEqual(r.status_code, 200)
        self.assertIn("running", r.json())


if __name__ == "__main__":
    unittest.main()