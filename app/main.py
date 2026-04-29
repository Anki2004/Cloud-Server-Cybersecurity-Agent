import asyncio
import os
import uuid
import re
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel
from enum import Enum

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from crewai import Crew, Process, Task
from langchain_groq import ChatGroq

# ── Agents ────────────────────────────────────────────────────────────────────
from agents.detection_agent import detection_agent
from agents.threat_analyst import threat_analyst
from agents.vulnerability_researcher import vulnerability_researcher
from agents.incident_advisor import incident_response_advisor
from agents.report_writer import cybersecurity_writer
from agents.risk_scorer import risk_scorer

# ── Task templates ─────────────────────────────────────────────────────────────
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

# ── Config from env ────────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL     = os.getenv("SLACK_WEBHOOK_URL", "")
CLOUDWATCH_LOG_GROUP  = os.getenv("CLOUDWATCH_LOG_GROUP", "")
CLOUDWATCH_LOG_STREAM = os.getenv("CLOUDWATCH_LOG_STREAM", "")
AWS_REGION            = os.getenv("AWS_REGION", "ap-south-1")
SCHEDULER_INTERVAL_MIN = int(os.getenv("SCHEDULER_INTERVAL_MIN", "5"))
DEFAULT_LOG_PATHS     = os.getenv("DEFAULT_LOG_PATHS", "/var/log/auth.log,/var/log/syslog")
DEFAULT_SCAN_HOURS    = int(os.getenv("DEFAULT_SCAN_HOURS", "24"))

_EXECUTOR = ThreadPoolExecutor(max_workers=8)

app = FastAPI(
    title="Multi-Agent Cybersecurity Intelligence System",
    description=(
        "A 6-agent CrewAI system with auto-scheduling, Slack alerting, "
        "and CloudWatch log ingestion. "
        "Phase 2 runs ThreatAnalyst ∥ VulnerabilityResearcher in parallel."
    ),
    version="4.0.0",
)

from app.job_store import JobStore
jobs = JobStore()



# ── Request / Response Models ──────────────────────────────────────────────────

class RunMode(str, Enum):
    detect   = "detect"
    research = "research"


class CrewRequest(BaseModel):
    mode:       RunMode = RunMode.detect
    query:      str     = "latest cybersecurity threats 2024"
    log_paths:  str     = DEFAULT_LOG_PATHS
    scan_hours: int     = DEFAULT_SCAN_HOURS


# ── CloudWatch Log Fetcher ─────────────────────────────────────────────────────

def fetch_cloudwatch_logs(log_group: str, log_stream: str, hours: int = 24) -> str:
    """
    Pull logs from CloudWatch and write to a temp file.
    Returns file path usable by LogAnalysisTool, or empty string on failure.
    """
    try:
        import boto3
        client = boto3.client("logs", region_name=AWS_REGION)
        start_time = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
        end_time   = int(datetime.now(timezone.utc).timestamp() * 1000)

        response = client.get_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            startTime=start_time,
            endTime=end_time,
            limit=10000,
        )
        events = response.get("events", [])
        if not events:
            logger.warning("CloudWatch returned 0 events")
            return ""

        tmp_path = "/tmp/cloudwatch_logs.log"
        with open(tmp_path, "w") as f:
            for event in events:
                f.write(event.get("message", "") + "\n")

        logger.info(f"CloudWatch: {len(events)} events written to {tmp_path}")
        return tmp_path

    except ImportError:
        logger.warning("boto3 not installed — skipping CloudWatch")
        return ""
    except Exception as e:
        logger.error(f"CloudWatch fetch failed: {e}")
        return ""


def resolve_log_paths(log_paths: str, scan_hours: int) -> str:
    """
    If CloudWatch is configured, fetch logs and prepend path.
    Falls back to file-based log_paths if CloudWatch unavailable.
    """
    if CLOUDWATCH_LOG_GROUP and CLOUDWATCH_LOG_STREAM:
        cw_path = fetch_cloudwatch_logs(CLOUDWATCH_LOG_GROUP, CLOUDWATCH_LOG_STREAM, scan_hours)
        if cw_path:
            return f"{cw_path},{log_paths}"
    return log_paths


# ── Slack Alerting ─────────────────────────────────────────────────────────────

def _extract_severity(report: str) -> str:
    """Best-effort severity extraction from report text."""
    report_lower = report.lower()
    if any(w in report_lower for w in ["critical", "severity: critical", "risk: critical"]):
        return "CRITICAL"
    if any(w in report_lower for w in ["high", "severity: high", "risk: high"]):
        return "HIGH"
    if any(w in report_lower for w in ["medium", "severity: medium"]):
        return "MEDIUM"
    return "LOW"


def send_slack_alert(job_id: str, severity: str, summary: str):
    """Send Slack webhook if SLACK_WEBHOOK_URL is set and severity >= HIGH."""
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack webhook not configured — skipping alert")
        return
    if severity not in ("HIGH", "CRITICAL"):
        logger.info(f"Severity {severity} below threshold — no Slack alert")
        return

    color   = "#FF0000" if severity == "CRITICAL" else "#FFA500"
    emoji   = "🚨" if severity == "CRITICAL" else "⚠️"
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} {severity} Threat Detected — Job {job_id[:8]}",
                "text": summary[:500],
                "footer": "Multi-Agent Cybersec System",
                "ts": int(datetime.now().timestamp()),
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Job ID",   "value": job_id[:8], "short": True},
                ],
            }
        ]
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
        logger.info(f"Slack alert sent for job {job_id[:8]} [{severity}]")
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")


# ── Crew Builders ──────────────────────────────────────────────────────────────

def build_detection_crew(log_paths: str, scan_hours: int) -> Crew:
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
    merged_context = (
        "=== THREAT INTELLIGENCE (from Threat Analyst) ===\n\n"
        f"{threat_output}\n\n"
        "=== VULNERABILITY DATA (from Vulnerability Researcher) ===\n\n"
        f"{vuln_output}"
    )
    incident_task_rt = Task(
        description=f"{merged_context}\n\n---\n{incident_response_task.description}",
        expected_output=incident_response_task.expected_output,
        agent=incident_response_advisor,
    )
    report_task_rt = Task(
        description=f"{merged_context}\n\n---\n{write_threat_report_task.description}",
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
    logger.info("Phase 2: launching parallel ThreatAnalyst ∥ VulnerabilityResearcher")
    threat_future = _EXECUTOR.submit(_run_threat_crew)
    vuln_future   = _EXECUTOR.submit(_run_vulnerability_crew)
    threat_output = vuln_output = ""
    errors = []

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

    downstream_output = _run_downstream_crew(threat_output, vuln_output)
    return threat_output, vuln_output, downstream_output


# ── Helpers ────────────────────────────────────────────────────────────────────

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
    jobs[job_id].setdefault("phase_timings", {})[phase] = {
        "started_at": datetime.now().isoformat()
    }
    jobs[job_id]["phase"] = phase


def _phase_end(job_id: str, phase: str):
    jobs[job_id].setdefault("phase_timings", {}).setdefault(phase, {})[
        "finished_at"
    ] = datetime.now().isoformat()


# ── Background Job Runners ─────────────────────────────────────────────────────

def run_detect_mode(job_id: str, request: CrewRequest):
    logger.info(f"[{job_id}] DETECT mode started")
    jobs.update_job(job_id,({"status": "running"})) 
    _phase_start(job_id, "detection")

    try:
        # Resolve logs — CloudWatch or file
        resolved_paths = resolve_log_paths(request.log_paths, request.scan_hours)

        # Phase 1
        detection_output = build_detection_crew(resolved_paths, request.scan_hours).kickoff()
        if isinstance(detection_output, dict):
            detection_output = detection_output.get("final_output", "")
        else:
            detection_output = str(detection_output)

        _phase_end(job_id, "detection")
        detection_path = _save_report(job_id, detection_output, prefix="detection")
        jobs.update_job(job_id,({
            "detection_report":      detection_output,
            "detection_report_file": detection_path,
        }))

        if _no_threats_found(detection_output):
            logger.info(f"[{job_id}] System clean — skipping intelligence pipeline")
            jobs.update_job(job_id,({
                "status":       "completed",
                "phase":        "completed",
                "escalated":    False,
                "result":       detection_output,
                "summary":      "System scan completed. No active threats detected.",
                "completed_at": datetime.now().isoformat(),
            }))
            return

        # Phase 2: parallel intelligence
        _phase_start(job_id, "intelligence")
        jobs[job_id]["escalated"] = True

        threat_out, vuln_out, downstream_out = build_intelligence_crew_parallel()
        _phase_end(job_id, "intelligence")

        intel_output = (
            "### Threat Intelligence\n\n" + threat_out + "\n\n"
            "### Vulnerability Research\n\n" + vuln_out + "\n\n"
            "### Incident Response, Report & Risk Scoring\n\n" + downstream_out
        )
        combined = (
            "## Phase 1 — Detection Report\n\n" + detection_output + "\n\n---\n\n"
            "## Phase 2 — Threat Intelligence & Risk Analysis\n\n" + intel_output
        )
        report_path = _save_report(job_id, combined, prefix="full_report")

        # Slack alert
        severity = _extract_severity(combined)
        summary  = downstream_out[:300]
        send_slack_alert(job_id, severity, summary)

        jobs.update_job(job_id,({
            "status":               "completed",
            "phase":                "completed",
            "result":               combined,
            "intelligence_report":  intel_output,
            "output_file":          report_path,
            "severity":             severity,
            "completed_at":         datetime.now().isoformat(),
        }))
        logger.info(f"[{job_id}] DETECT mode completed [{severity}]")

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}", exc_info=True)
        jobs.update_job(job_id,({
            "status":    "failed",
            "error":     str(e),
            "failed_at": datetime.now().isoformat(),
        }))


def run_research_mode(job_id: str, request: CrewRequest):
    logger.info(f"[{job_id}] RESEARCH mode started: {request.query}")
    jobs.update_job(job_id,({"status": "running"}))
    _phase_start(job_id, "intelligence")

    try:
        threat_out, vuln_out, downstream_out = build_intelligence_crew_parallel()
        _phase_end(job_id, "intelligence")

        output = (
            "### Threat Intelligence\n\n" + threat_out + "\n\n"
            "### Vulnerability Research\n\n" + vuln_out + "\n\n"
            "### Incident Response, Report & Risk Scoring\n\n" + downstream_out
        )
        report_path = _save_report(job_id, output, prefix="research")

        severity = _extract_severity(output)
        send_slack_alert(job_id, severity, downstream_out[:300])

        jobs.update_job(job_id,({
            "status":       "completed",
            "phase":        "completed",
            "escalated":    False,
            "result":       output,
            "output_file":  report_path,
            "severity":     severity,
            "completed_at": datetime.now().isoformat(),
        }))

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}", exc_info=True)
        jobs.update_job(job_id,({
            "status":    "failed",
            "error":     str(e),
            "failed_at": datetime.now().isoformat(),
        }))


# ── Scheduler ─────────────────────────────────────────────────────────────────

def scheduled_detect_job():
    """Auto-triggered detect scan — runs every SCHEDULER_INTERVAL_MIN minutes."""
    job_id = str(uuid.uuid4())
    logger.info(f"[SCHEDULER] Auto-scan triggered → job {job_id[:8]}")
    jobs[job_id] = {
        "job_id":        job_id,
        "mode":          "detect",
        "query":         "scheduled auto-scan",
        "log_paths":     DEFAULT_LOG_PATHS,
        "scan_hours":    DEFAULT_SCAN_HOURS,
        "status":        "queued",
        "phase":         "queued",
        "escalated":     None,
        "phase_timings": {},
        "created_at":    datetime.now().isoformat(),
        "scheduled":     True,
    }
    request = CrewRequest(
        mode=RunMode.detect,
        log_paths=DEFAULT_LOG_PATHS,
        scan_hours=DEFAULT_SCAN_HOURS,
    )
    _EXECUTOR.submit(run_detect_mode, job_id, request)


scheduler = BackgroundScheduler()
scheduler.add_job(
    scheduled_detect_job,
    trigger=IntervalTrigger(minutes=SCHEDULER_INTERVAL_MIN),
    id="auto_detect",
    name=f"Auto detect every {SCHEDULER_INTERVAL_MIN} min",
    replace_existing=True,
)


@app.on_event("startup")
def startup():
    scheduler.start()
    logger.info(f"Scheduler started — auto-scan every {SCHEDULER_INTERVAL_MIN} min")


@app.on_event("shutdown")
def shutdown():
    scheduler.shutdown()
    logger.info("Scheduler stopped")


# ── API Endpoints ──────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Multi-Agent Cybersecurity Intelligence System v4.0",
        "whats_new": [
            f"Auto-scan every {SCHEDULER_INTERVAL_MIN} min via APScheduler",
            "Slack webhook alerts for HIGH/CRITICAL threats",
            "CloudWatch log ingestion via boto3 (set CLOUDWATCH_LOG_GROUP env var)",
        ],
        "endpoints": {
            "POST /run":              "Submit a job",
            "GET  /results/{job_id}": "Poll job status",
            "GET  /jobs":             "List all jobs",
            "DELETE /jobs":           "Clear job history",
            "GET  /scheduler":        "Scheduler status",
            "GET  /health":           "Health check",
        },
    }


@app.get("/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.now().isoformat(),
        "scheduler": scheduler.running,
        "slack":     bool(SLACK_WEBHOOK_URL),
        "cloudwatch": bool(CLOUDWATCH_LOG_GROUP),
    }


@app.get("/scheduler")
def scheduler_status():
    jobs_list = [
        {
            "id":           j.id,
            "name":         j.name,
            "next_run_time": str(j.next_run_time),
        }
        for j in scheduler.get_jobs()
    ]
    return {"running": scheduler.running, "jobs": jobs_list}


@app.post("/scheduler/pause")
def pause_scheduler():
    scheduler.pause()
    return {"status": "paused"}


@app.post("/scheduler/resume")
def resume_scheduler():
    scheduler.resume()
    return {"status": "resumed"}


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
        "scheduled":     False,
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
            "job_id":       j["job_id"],
            "mode":         j.get("mode"),
            "status":       j.get("status"),
            "phase":        j.get("phase"),
            "escalated":    j.get("escalated"),
            "severity":     j.get("severity"),
            "scheduled":    j.get("scheduled", False),
            "phase_timings":j.get("phase_timings", {}),
            "created_at":   j.get("created_at"),
            "completed_at": j.get("completed_at"),
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

@app.get("/benchmark")
def run_accuracy_benchmark():
    """Run detection accuracy benchmark — returns accuracy metrics."""
    import subprocess
    result = subprocess.run(
        ["python", "tests/benchmarks/run_benchmark.py"],
        capture_output=True, text=True, cwd="/app"
    )
    try:
        with open("/app/tests/benchmarks/benchmark_report.json") as f:
            import json
            return json.load(f)
    except Exception:
        return {"error": result.stderr, "output": result.stdout}