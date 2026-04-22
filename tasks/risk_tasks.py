from crewai import Task
from agents.risk_scorer import risk_scorer
from tasks.report_tasks import write_threat_report_task

risk_scoring_task = Task(
    description=(
        "Read the final cybersecurity report produced by the report writer. "
        "For each threat and CVE mentioned, produce a structured risk matrix in markdown table format with columns: "
        "| Threat/CVE | Severity | Likelihood (1-5) | Business Impact (1-5) | Risk Score (Likelihood x Impact) | Priority |. "
        "Severity must be one of: Critical, High, Medium, Low. "
        "End with a short paragraph summarizing the overall risk posture."
    ),
    expected_output=(
        "A markdown risk matrix table covering all identified threats and CVEs, "
        "with severity, likelihood, impact, risk score, and priority columns. "
        "Followed by a 2-3 sentence overall risk posture summary."
    ),
    agent=risk_scorer,
    context=[write_threat_report_task],
)
