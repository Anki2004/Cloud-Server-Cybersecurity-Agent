import streamlit as st
import requests
import time

API_BASE = "http://localhost:8000"

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
        query = "latest cybersecurity threats 2024"  # used if escalated
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
        st.markdown("- 🖥️ Cloud Security Detection Agent *(new)*")
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

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Detection Report",
    "🌐 Intelligence Report",
    "📊 Risk Matrix",
    "📁 Job History"
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

    # ── Progress polling ───────────────────────────────────────────────────
    phase_labels = {
        "queued":       "⏳ Queued...",
        "detection":    "🔍 Phase 1: Scanning server (logs, network, filesystem)...",
        "intelligence": "🧠 Phase 2: Running intelligence pipeline (5 agents)...",
        "completed":    "✅ Complete!",
        "failed":       "❌ Failed",
    }

    progress_bar = st.progress(0, text="Starting...")
    status_box   = st.empty()

    for i in range(200):  # poll up to ~10 mins
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

with tab1:
    if result:
        escalated = result.get("escalated")
        st.markdown(f"**Job:** `{result['job_id']}`  |  **Mode:** `{result.get('mode')}`  |  **Escalated:** `{escalated}`")

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

with tab2:
    if result:
        intel = result.get("intelligence_report") or (
            result.get("result") if result.get("mode") == "research" else None
        )
        if intel:
            if result.get("escalated"):
                st.warning("⚠️ Intelligence pipeline was triggered because active threats were detected.")
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

with tab3:
    if result:
        report_text = result.get("intelligence_report") or result.get("result", "")
        if "|" in report_text and ("Severity" in report_text or "Risk Score" in report_text):
            # Extract markdown table lines
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

with tab4:
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
            jobs_res = requests.get(f"{API_BASE}/jobs", timeout=5).json()
            jobs_list = jobs_res.get("jobs", [])
            if jobs_list:
                for job in jobs_list:
                    icon = {"completed": "✅", "running": "⏳", "failed": "❌", "queued": "🕐"}.get(job["status"], "❓")
                    escalated_str = {True: "Yes — threats found", False: "No — system clean", None: "Pending"}.get(job.get("escalated"), "—")
                    with st.expander(f"{icon} `{job['job_id'][:12]}...`  |  {job.get('mode', '').upper()}  |  {job['status']}"):
                        st.markdown(f"**Phase:** `{job.get('phase')}`")
                        st.markdown(f"**Escalated:** {escalated_str}")
                        st.markdown(f"**Created:** {job.get('created_at', 'N/A')}")
                        st.markdown(f"**Completed:** {job.get('completed_at', 'N/A')}")
            else:
                st.info("No jobs yet.")
        except Exception as e:
            st.error(f"Could not fetch jobs: {e}")
