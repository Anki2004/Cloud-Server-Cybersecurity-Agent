import streamlit as st
import requests
import time
import pandas as pd
from datetime import datetime

API_BASE = "http://api:8000"

st.set_page_config(
    page_title="Cybersecurity Intelligence System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Multi-Agent Cybersecurity Intelligence System")
st.caption("6 Agents · CrewAI · Groq Llama3-70b · Exa · NVD · Log/Network/Filesystem Detection")

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    mode = st.radio(
        "Operation Mode",
        options=["detect", "research"],
        format_func=lambda x: "🔍 Detect — Scan Server" if x == "detect" else "🌐 Research — Threat Intel",
        help="Detect: scans your cloud server and escalates threats.\nResearch: standalone threat intelligence."
    )

    st.divider()

    if mode == "detect":
        st.markdown("**Detection Settings**")
        log_paths = st.text_input(
            "Log file paths (comma-separated)",
            value="/var/log/auth.log,/var/log/syslog"
        )
        scan_hours = st.slider("Scan window (hours back)", 1, 72, 24)
        query = "latest cybersecurity threats 2024"
    else:
        st.markdown("**Research Settings**")
        query = st.text_input("Threat query", value="latest cybersecurity threats 2024")
        log_paths = "/var/log/auth.log,/var/log/syslog"
        scan_hours = 24

    st.divider()
    run_btn = st.button("🚀 Run", use_container_width=True, type="primary")

    st.divider()
    st.markdown("**Agents in this system:**")
    if mode == "detect":
        st.markdown("- 🖥️ Cloud Security Detection Agent")
        st.markdown("- 🔍 Threat Intelligence Analyst")
        st.markdown("- 🧪 Vulnerability Researcher")
        st.markdown("- 🛠️ Incident Response Advisor")
        st.markdown("- 📝 Report Writer")
        st.markdown("- 📊 Risk Scorer")
    else:
        st.markdown("- 🔍 Threat Intelligence Analyst")
        st.markdown("- 🧪 Vulnerability Researcher")
        st.markdown("- 🛠️ Incident Response Advisor")
        st.markdown("- 📝 Report Writer")
        st.markdown("- 📊 Risk Scorer")


# ── Metrics Helper ────────────────────────────────────────────────────────────
def fetch_jobs():
    try:
        res = requests.get(f"{API_BASE}/jobs", timeout=5).json()
        return res.get("jobs", [])
    except:
        return []


def compute_metrics(jobs_list):
    total       = len(jobs_list)
    completed   = sum(1 for j in jobs_list if j["status"] == "completed")
    failed      = sum(1 for j in jobs_list if j["status"] == "failed")
    escalated   = sum(1 for j in jobs_list if j.get("escalated") is True)
    critical    = sum(1 for j in jobs_list if j.get("severity") in ("CRITICAL", "HIGH"))
    scheduled   = sum(1 for j in jobs_list if j.get("scheduled", False))
    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "escalated": escalated,
        "critical": critical,
        "scheduled": scheduled,
    }


def build_trend_data(jobs_list):
    """Build per-scan threat detection trend."""
    rows = []
    for job in jobs_list:
        if job["status"] != "completed" or not job.get("completed_at"):
            continue
        try:
            ts = datetime.fromisoformat(job["completed_at"])
        except:
            continue
        rows.append({
            "Time": ts,
            "Threats": 1 if job.get("escalated") else 0,
            "Severity": job.get("severity", "LOW"),
            "Mode": job.get("mode", "detect"),
        })
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows).sort_values("Time")
    df["Scan #"] = range(1, len(df) + 1)
    return df


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋 Detection Report",
    "🌐 Intelligence Report",
    "📊 Risk Matrix",
    "📈 Threat Trends",
    "📁 Job History",
])

# ── Run Job ───────────────────────────────────────────────────────────────────
if run_btn:
    payload = {
        "mode": mode,
        "query": query,
        "log_paths": log_paths,
        "scan_hours": scan_hours,
    }
    with st.spinner("Submitting job..."):
        try:
            res = requests.post(f"{API_BASE}/run", json=payload, timeout=10)
            res.raise_for_status()
            job_data = res.json()
            job_id = job_data["job_id"]
            st.session_state["job_id"] = job_id
            st.session_state["last_result"] = None
            st.success(f"Job queued — ID: `{job_id}`")
        except Exception as e:
            st.error(f"Failed to submit job: {e}")
            st.stop()

    phase_labels = {
        "queued":       "⏳ Queued...",
        "detection":    "🔍 Phase 1: Scanning server (logs, network, filesystem)...",
        "intelligence": "🧠 Phase 2: Running intelligence pipeline (5 agents)...",
        "completed":    "✅ Complete!",
        "failed":       "❌ Failed",
    }

    progress_bar = st.progress(0, text="Starting...")
    status_box   = st.empty()

    for i in range(200):
        time.sleep(3)
        try:
            poll = requests.get(f"{API_BASE}/results/{job_id}", timeout=5).json()
            status = poll.get("status", "queued")
            phase  = poll.get("phase", "queued")

            label = phase_labels.get(phase, f"Status: {phase}")
            progress_val = {
                "queued": 0.05,
                "detection": 0.35,
                "intelligence": 0.70,
                "completed": 1.0,
                "failed": 1.0,
            }.get(phase, 0.1)

            progress_bar.progress(progress_val, text=label)
            status_box.info(f"**Phase:** {phase}  |  **Escalated:** {poll.get('escalated')}")

            if status == "completed":
                st.session_state["last_result"] = poll
                st.rerun()
            elif status == "failed":
                st.error(f"Job failed: {poll.get('error')}")
                st.stop()
        except Exception as e:
            st.warning(f"Polling error: {e}")

# ── Display Results ───────────────────────────────────────────────────────────
result = st.session_state.get("last_result")

# ── Metrics Banner (always visible) ──────────────────────────────────────────
jobs_list = fetch_jobs()
metrics   = compute_metrics(jobs_list)

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Total Scans",      metrics["total"])
m2.metric("Completed",        metrics["completed"])
m3.metric("Failed",           metrics["failed"])
m4.metric("Threats Found",    metrics["escalated"])
m5.metric("High/Critical",    metrics["critical"])
m6.metric("Auto Scans",       metrics["scheduled"])

st.divider()

# ── Tab 1: Detection Report ───────────────────────────────────────────────────
with tab1:
    if result:
        escalated = result.get("escalated")
        sev = result.get("severity", "—")
        sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")

        st.markdown(
            f"**Job:** `{result['job_id']}`  |  "
            f"**Mode:** `{result.get('mode')}`  |  "
            f"**Escalated:** `{escalated}`  |  "
            f"**Severity:** {sev_color} `{sev}`"
        )

        if escalated is False and result.get("mode") == "detect":
            st.success("✅ System scan completed — no active threats detected on the server.")
        elif result.get("detection_report"):
            st.subheader("Phase 1 — Detection Findings")
            st.markdown(result["detection_report"])
            st.download_button(
                "⬇️ Download Detection Report (.md)",
                data=result["detection_report"],
                file_name="detection_report.md",
                mime="text/markdown"
            )
        else:
            st.info("Detection report not available (Research mode was used).")
    else:
        st.info("Run the system in Detect mode to see detection results here.")

# ── Tab 2: Intelligence Report ────────────────────────────────────────────────
with tab2:
    if result:
        intel = result.get("intelligence_report") or (
            result.get("result") if result.get("mode") == "research" else None
        )
        if intel:
            if result.get("escalated"):
                st.warning("⚠️ Intelligence pipeline triggered — active threats detected.")
            st.markdown(intel)
            st.download_button(
                "⬇️ Download Intelligence Report (.md)",
                data=intel,
                file_name="intelligence_report.md",
                mime="text/markdown"
            )
        elif result.get("escalated") is False and result.get("mode") == "detect":
            st.success("No intelligence report generated — server was clean.")
        else:
            st.info("No intelligence report available yet.")
    else:
        st.info("Run the system to see the threat intelligence report here.")

# ── Tab 3: Risk Matrix ────────────────────────────────────────────────────────
with tab3:
    if result:
        report_text = result.get("intelligence_report") or result.get("result", "")
        if "|" in report_text and ("Severity" in report_text or "Risk Score" in report_text):
            lines = report_text.split("\n")
            in_table, table_lines = False, []
            for line in lines:
                if "|" in line and not in_table:
                    in_table = True
                if in_table:
                    if line.strip() == "" and table_lines:
                        break
                    table_lines.append(line)
            if table_lines:
                st.subheader("Risk Matrix")
                st.markdown("\n".join(table_lines))
            else:
                st.markdown(report_text)
        else:
            st.info("Risk matrix will appear here once the intelligence pipeline completes.")
    else:
        st.info("Run the system to see the risk matrix here.")

# ── Tab 4: Threat Trends ──────────────────────────────────────────────────────
with tab4:
    st.subheader("📈 Threat Detection Trends")

    if not jobs_list:
        st.info("No scan history yet. Run a few scans to see trends.")
    else:
        df = build_trend_data(jobs_list)

        if df.empty:
            st.info("No completed scans yet.")
        else:
            # ── Summary stats ──────────────────────────────────────────────
            c1, c2, c3, c4 = st.columns(4)
            total_scans    = len(df)
            threat_scans   = df["Threats"].sum()
            clean_scans    = total_scans - threat_scans
            threat_rate    = round((threat_scans / total_scans) * 100, 1) if total_scans else 0

            c1.metric("Total Scans",    total_scans)
            c2.metric("Threats Found",  int(threat_scans))
            c3.metric("Clean Scans",    int(clean_scans))
            c4.metric("Threat Rate",    f"{threat_rate}%")

            st.divider()

            # ── Threat detection line chart ────────────────────────────────
            st.markdown("**Threat Detections per Scan**")
            chart_df = df[["Scan #", "Threats"]].set_index("Scan #")
            st.line_chart(chart_df, use_container_width=True)

            # ── Severity breakdown bar chart ───────────────────────────────
            st.markdown("**Severity Breakdown**")
            sev_counts = df["Severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            sev_counts["Severity"] = pd.Categorical(sev_counts["Severity"], categories=sev_order, ordered=True)
            sev_counts = sev_counts.sort_values("Severity")
            st.bar_chart(sev_counts.set_index("Severity"), use_container_width=True)

            # ── Mode breakdown ─────────────────────────────────────────────
            st.markdown("**Scan Mode Breakdown**")
            mode_counts = df["Mode"].value_counts()
            st.bar_chart(mode_counts, use_container_width=True)

            # ── Recent scan table ──────────────────────────────────────────
            st.markdown("**Last 10 Scans**")
            display_df = df[["Scan #", "Time", "Threats", "Severity", "Mode"]].tail(10).copy()
            display_df["Time"] = display_df["Time"].dt.strftime("%Y-%m-%d %H:%M")
            display_df["Threats"] = display_df["Threats"].map({1: "⚠️ Yes", 0: "✅ No"})
            st.dataframe(display_df, use_container_width=True, hide_index=True)

# ── Tab 5: Job History ────────────────────────────────────────────────────────
with tab5:
    col1, col2 = st.columns([1, 5])
    with col1:
        refresh = st.button("🔄 Refresh")
    with col2:
        clear = st.button("🗑️ Clear All Jobs")

    if clear:
        try:
            requests.delete(f"{API_BASE}/jobs")
            st.session_state["last_result"] = None
            st.success("All jobs cleared.")
        except Exception as e:
            st.error(f"Could not clear jobs: {e}")

    if refresh or True:
        try:
            jobs_res  = requests.get(f"{API_BASE}/jobs", timeout=5).json()
            jobs_list = jobs_res.get("jobs", [])
            if jobs_list:
                for job in jobs_list:
                    icon = {"completed": "✅", "running": "⏳", "failed": "❌", "queued": "🕐"}.get(job["status"], "❓")
                    sev  = job.get("severity", "—")
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
                    scheduled_tag = " 🤖" if job.get("scheduled") else ""
                    escalated_str = {True: "⚠️ Threats found", False: "✅ Clean", None: "Pending"}.get(job.get("escalated"), "—")

                    with st.expander(
                        f"{icon} `{job['job_id'][:12]}...`  |  "
                        f"{job.get('mode','').upper()}  |  "
                        f"{job['status']}  |  "
                        f"{sev_icon} {sev}{scheduled_tag}"
                    ):
                        st.markdown(f"**Phase:** `{job.get('phase')}`")
                        st.markdown(f"**Escalated:** {escalated_str}")
                        st.markdown(f"**Scheduled:** {'Yes 🤖' if job.get('scheduled') else 'No'}")
                        st.markdown(f"**Created:** {job.get('created_at', 'N/A')}")
                        st.markdown(f"**Completed:** {job.get('completed_at', 'N/A')}")

                        timings = job.get("phase_timings", {})
                        if timings:
                            st.markdown("**Phase Timings:**")
                            for phase, t in timings.items():
                                start = t.get("started_at", "")
                                end   = t.get("finished_at", "")
                                if start and end:
                                    try:
                                        duration = (
                                            datetime.fromisoformat(end) - datetime.fromisoformat(start)
                                        ).seconds
                                        st.markdown(f"- `{phase}`: {duration}s")
                                    except:
                                        st.markdown(f"- `{phase}`: {start} → {end}")
            else:
                st.info("No jobs yet.")
        except Exception as e:
            st.error(f"Could not fetch jobs: {e}")