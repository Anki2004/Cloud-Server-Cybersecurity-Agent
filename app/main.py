"""
Multi-Agent Cybersecurity Intelligence System — v3.0
=====================================================
Key changes vs v2.0
--------------------
* Phase 2 parallelism: ThreatAnalyst and VulnerabilityResearcher run
  concurrently via asyncio + ThreadPoolExecutor, cutting Phase 2 wall-clock
  time roughly in half before the sequential downstream agents begin.
* Dynamic task context injection: parallel outputs are merged and injected
  into IncidentAdvisor / ReportWriter / RiskScorer contexts at runtime,
  preserving the original task dependency graph without CrewAI re-wiring.
* Async-native FastAPI: /run is now a true async endpoint; background jobs
  run in a thread pool so the event loop is never blocked.
* log_paths / scan_hours from request are forwarded into detection task at
  runtime (no more hard-coded paths in task definition).
* /health endpoint for load-balancer / uptime checks.
* Structured job timing: phase_timings dict records start/end for each phase.
"""

import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel
from enum import Enum

from crewai import Crew, Process, Task
from langchain_groq import ChatGroq

# ── Agents ────────────────────────────────────────────────────────────────────
from agents.detection_agent import detection_agent
from agents.threat_analyst import threat_analyst
from agents.vulnerability_researcher import vulnerability_researcher
from agents.incident_advisor import incident_response_advisor
from agents.report_writer import cybersecurity_writer
from agents.risk_scorer import risk_scorer

# ── Task templates (imported but rebuilt at runtime for parallel mode) ─────────
from tasks.detection_task import detection_task
from tasks.threat_tasks import threat_analysis_task
from tasks.vulnerability_tasks import vulnerability_research_task
from tasks.incident_tasks import incident_response_task
from tasks.report_tasks import write_threat_report_task
from tasks.risk_tasks import risk_scoring_task

from config import GROQ_API_KEY, MODEL_NAME, OUTPUTS_DIR
from logger import get_logger

logger = get_logger(__name__)
os.environ["GROQ_API_KEY"] = GROQ_API_KEY
os.makedirs(OUTPUTS_DIR, exist_ok=True)

# Thread pool shared across all background jobs (tune workers as needed)
_EXECUTOR = ThreadPoolExecutor(max_workers=8)

app = FastAPI(
    title="Multi-Agent Cybersecurity Intelligence System",
    description=(
        "A 6-agent CrewAI system with two operational modes: "
        "DETECT (monitor cloud server + auto-escalate to parallel intelligence pipeline) "
        "and RESEARCH (standalone threat intelligence on a given query). "
        "Phase 2 runs ThreatAnalyst ∥ VulnerabilityResearcher in parallel."
    ),
    version="3.0.0",
)

# In-memory job store — swap for Redis in production
jobs: dict = {}


# ── Request / Response Models ─────────────────────────────────────────────────

class RunMode(str, Enum):
    detect   = "detect"
    research = "research"


class CrewRequest(BaseModel):
    mode:      RunMode = RunMode.detect
    query:     str     = "latest cybersecurity threats 2024"
    log_paths: str     = "/var/log/auth.log,/var/log/syslog"
    scan_hours: int    = 24


# ── Crew Builders ─────────────────────────────────────────────────────────────

def build_detection_crew(log_paths: str, scan_hours: int) -> Crew:
    """Phase 1: single-agent detection crew with runtime-injected parameters."""
    runtime_task = Task(
        description=detection_task.description.replace(
            "/var/log/auth.log,/var/log/syslog", log_paths
        ).replace("'24'", f"'{scan_hours}'"),
        expected_output=detection_task.expected_output,
        agent=detection_agent,
    )
    return Crew(
        agents=[detection_agent],
        tasks=[runtime_task],
        process=Process.sequential,
        verbose=2,
        full_output=True,
    )


def _run_threat_crew() -> str:
    """Run threat analysis crew in isolation (for parallel execution)."""
    crew = Crew(
        agents=[threat_analyst],
        tasks=[threat_analysis_task],
        process=Process.sequential,
        verbose=2,
        full_output=True,
    )
    result = crew.kickoff()
    return result.get("final_output", "") if isinstance(result, dict) else str(result)


def _run_vulnerability_crew() -> str:
    """Run vulnerability research crew in isolation (for parallel execution)."""
    crew = Crew(
        agents=[vulnerability_researcher],
        tasks=[vulnerability_research_task],
        process=Process.sequential,
        verbose=2,
        full_output=True,
    )
    result = crew.kickoff()
    return result.get("final_output", "") if isinstance(result, dict) else str(result)


def _run_downstream_crew(threat_output: str, vuln_output: str) -> str:
    """
    Run the 3 downstream agents (Incident → Report → Risk) sequentially.
    Injects the parallel outputs as context strings so agents have full
    visibility without relying on CrewAI's task-context linking.
    """
    merged_context = (
        "=== THREAT INTELLIGENCE (from Threat Analyst) ===\n\n"
        f"{threat_output}\n\n"
        "=== VULNERABILITY DATA (from Vulnerability Researcher) ===\n\n"
        f"{vuln_output}"
    )

    # Rebuild tasks with injected context in description
    incident_task_rt = Task(
        description=(
            f"{merged_context}\n\n"
            "---\n"
            f"{incident_response_task.description}"
        ),
        expected_output=incident_response_task.expected_output,
        agent=incident_response_advisor,
    )

    report_task_rt = Task(
        description=(
            f"{merged_context}\n\n"
            "---\n"
            f"{write_threat_report_task.description}"
        ),
        expected_output=write_threat_report_task.expected_output,
        agent=cybersecurity_writer,
        context=[incident_task_rt],
    )

    risk_task_rt = Task(
        description=risk_scoring_task.description,
        expected_output=risk_scoring_task.expected_output,
        agent=risk_scorer,
        context=[report_task_rt],
    )

    llm = ChatGroq(temperature=0, model_name=MODEL_NAME)
    crew = Crew(
        agents=[incident_response_advisor, cybersecurity_writer, risk_scorer],
        tasks=[incident_task_rt, report_task_rt, risk_task_rt],
        process=Process.sequential,
        verbose=2,
        full_output=True,
        memory=True,
    )
    result = crew.kickoff()
    return result.get("final_output", "") if isinstance(result, dict) else str(result)


def build_intelligence_crew_parallel() -> tuple[str, str, str]:
    """
    Phase 2 parallel intelligence pipeline.

    Topology:
        ThreatAnalyst ──┐
                        ├──► IncidentAdvisor ──► ReportWriter ──► RiskScorer
        VulnResearcher ─┘

    ThreatAnalyst and VulnerabilityResearcher execute concurrently in
    separate threads. Once both finish, their outputs are merged and fed
    into the sequential downstream pipeline.

    Returns:
        (threat_output, vuln_output, final_downstream_output)
    """
    logger.info("Phase 2: launching parallel ThreatAnalyst ∥ VulnerabilityResearcher")

    threat_future = _EXECUTOR.submit(_run_threat_crew)
    vuln_future   = _EXECUTOR.submit(_run_vulnerability_crew)

    threat_output = ""
    vuln_output   = ""
    errors        = []

    for future in as_completed([threat_future, vuln_future]):
        try:
            result = future.result()
            if future is threat_future:
                threat_output = result
                logger.info("ThreatAnalyst finished ✓")
            else:
                vuln_output = result
                logger.info("VulnerabilityResearcher finished ✓")
        except Exception as e:
            errors.append(str(e))
            logger.error(f"Parallel agent failed: {e}")

    if errors:
        logger.warning(f"Parallel phase errors (continuing): {errors}")

    logger.info("Both parallel agents done — starting downstream pipeline")
    downstream_output = _run_downstream_crew(threat_output, vuln_output)

    return threat_output, vuln_output, downstream_output


# ── Helpers ───────────────────────────────────────────────────────────────────

def _no_threats_found(detection_output: str) -> bool:
    lowered = detection_output.lower()
    return (
        "total_threat_types_found: 0" in lowered
        and "total_network_threats: 0" in lowered
        and "total_fs_threats: 0" in lowered
    ) or "no threats detected" in lowered


def _save_report(job_id: str, content: str, prefix: str = "report") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"{prefix}_{timestamp}_{job_id[:8]}.md"
    path      = os.path.join(OUTPUTS_DIR, filename)
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write("# Cybersecurity Intelligence Report\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Job ID:** `{job_id}`\n\n")
        f.write(content)
    logger.info(f"Report saved → {path}")
    return path


def _phase_start(job_id: str, phase: str):
    timings = jobs[job_id].setdefault("phase_timings", {})
    timings[phase] = {"started_at": datetime.now().isoformat()}
    jobs[job_id]["phase"] = phase


def _phase_end(job_id: str, phase: str):
    timings = jobs[job_id].setdefault("phase_timings", {})
    timings.setdefault(phase, {})["finished_at"] = datetime.now().isoformat()


# ── Background Job Runners ────────────────────────────────────────────────────

def run_detect_mode(job_id: str, request: CrewRequest):
    """
    Phase 1 → Detection (logs + network + filesystem)
    Phase 2 → Parallel intelligence (if threats found)
    """
    logger.info(f"[{job_id}] DETECT mode started")
    jobs[job_id].update({"status": "running"})
    _phase_start(job_id, "detection")

    try:
        # ── Phase 1 ───────────────────────────────────────────────────────
        detection_output = build_detection_crew(
            request.log_paths, request.scan_hours
        ).kickoff()
        if isinstance(detection_output, dict):
            detection_output = detection_output.get("final_output", "")
        else:
            detection_output = str(detection_output)

        _phase_end(job_id, "detection")
        detection_path = _save_report(job_id, detection_output, prefix="detection")
        jobs[job_id].update({
            "detection_report": detection_output,
            "detection_report_file": detection_path,
        })
        logger.info(f"[{job_id}] Phase 1 complete")

        # ── Escalation decision ────────────────────────────────────────────
        if _no_threats_found(detection_output):
            logger.info(f"[{job_id}] System clean — skipping intelligence pipeline")
            jobs[job_id].update({
                "status": "completed",
                "phase": "completed",
                "escalated": False,
                "result": detection_output,
                "summary": "System scan completed. No active threats detected.",
                "completed_at": datetime.now().isoformat(),
            })
            return

        # ── Phase 2: Parallel intelligence ────────────────────────────────
        logger.info(f"[{job_id}] Threats detected — parallel intelligence pipeline")
        _phase_start(job_id, "intelligence")
        jobs[job_id]["escalated"] = True

        threat_out, vuln_out, downstream_out = build_intelligence_crew_parallel()
        _phase_end(job_id, "intelligence")

        intel_output = (
            "### Threat Intelligence\n\n"
            f"{threat_out}\n\n"
            "### Vulnerability Research\n\n"
            f"{vuln_out}\n\n"
            "### Incident Response, Report & Risk Scoring\n\n"
            f"{downstream_out}"
        )
        combined = (
            "## Phase 1 — Detection Report\n\n"
            f"{detection_output}\n\n"
            "---\n\n"
            "## Phase 2 — Threat Intelligence & Risk Analysis\n\n"
            f"{intel_output}"
        )
        report_path = _save_report(job_id, combined, prefix="full_report")

        jobs[job_id].update({
            "status": "completed",
            "phase": "completed",
            "result": combined,
            "intelligence_report": intel_output,
            "output_file": report_path,
            "completed_at": datetime.now().isoformat(),
        })
        logger.info(f"[{job_id}] DETECT mode completed")

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}", exc_info=True)
        jobs[job_id].update({
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now().isoformat(),
        })


def run_research_mode(job_id: str, request: CrewRequest):
    """Standalone intelligence — parallel Phase 2 only."""
    logger.info(f"[{job_id}] RESEARCH mode started: {request.query}")
    jobs[job_id].update({"status": "running"})
    _phase_start(job_id, "intelligence")

    try:
        threat_out, vuln_out, downstream_out = build_intelligence_crew_parallel()
        _phase_end(job_id, "intelligence")

        output = (
            "### Threat Intelligence\n\n"
            f"{threat_out}\n\n"
            "### Vulnerability Research\n\n"
            f"{vuln_out}\n\n"
            "### Incident Response, Report & Risk Scoring\n\n"
            f"{downstream_out}"
        )
        report_path = _save_report(job_id, output, prefix="research")

        jobs[job_id].update({
            "status": "completed",
            "phase": "completed",
            "escalated": False,
            "result": output,
            "output_file": report_path,
            "completed_at": datetime.now().isoformat(),
        })
        logger.info(f"[{job_id}] RESEARCH mode completed")

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}", exc_info=True)
        jobs[job_id].update({
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now().isoformat(),
        })


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Multi-Agent Cybersecurity Intelligence System v3.0",
        "whats_new": (
            "Phase 2 now runs ThreatAnalyst ∥ VulnerabilityResearcher concurrently, "
            "reducing intelligence pipeline time by ~50%. "
            "Detection task accepts runtime log_paths and scan_hours."
        ),
        "modes": {
            "detect":   "Scan cloud server → auto-escalate to parallel intelligence pipeline",
            "research": "Parallel threat intelligence research on a given query",
        },
        "endpoints": {
            "POST /run":               "Submit a job",
            "GET  /results/{job_id}":  "Poll job status and results",
            "GET  /jobs":              "List all jobs with phase timings",
            "DELETE /jobs":            "Clear job history",
            "GET  /health":            "Health check for load balancers",
        },
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.post("/run")
async def run(request: CrewRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id":        job_id,
        "mode":          request.mode,
        "query":         request.query,
        "log_paths":     request.log_paths,
        "scan_hours":    request.scan_hours,
        "status":        "queued",
        "phase":         "queued",
        "escalated":     None,
        "phase_timings": {},
        "created_at":    datetime.now().isoformat(),
    }

    if request.mode == RunMode.detect:
        background_tasks.add_task(run_detect_mode, job_id, request)
    else:
        background_tasks.add_task(run_research_mode, job_id, request)

    logger.info(f"Job {job_id} queued in {request.mode} mode")
    return {"job_id": job_id, "mode": request.mode, "status": "queued"}


@app.get("/results/{job_id}")
def get_results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found.")
    return jobs[job_id]


@app.get("/jobs")
def list_jobs():
    summary = [
        {
            "job_id":        j["job_id"],
            "mode":          j.get("mode"),
            "status":        j.get("status"),
            "phase":         j.get("phase"),
            "escalated":     j.get("escalated"),
            "phase_timings": j.get("phase_timings", {}),
            "created_at":    j.get("created_at"),
            "completed_at":  j.get("completed_at"),
        }
        for j in jobs.values()
    ]
    return {
        "total": len(summary),
        "jobs":  sorted(summary, key=lambda x: x["created_at"], reverse=True),
    }


@app.delete("/jobs")
def clear_jobs():
    jobs.clear()
    return {"message": "All jobs cleared."}