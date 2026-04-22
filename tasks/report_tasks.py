from crewai import Task
from agents.report_writer import cybersecurity_writer
from tasks.threat_tasks import threat_analysis_task
from tasks.vulnerability_tasks import vulnerability_research_task
from tasks.incident_tasks import incident_response_task

write_threat_report_task = Task(
    description=(
        "Using all gathered intelligence from the threat analyst, vulnerability researcher, "
        "and incident response advisor, write a comprehensive cybersecurity intelligence report in markdown. "
        "The report must include: "
        "1. Executive Summary "
        "2. Top Threats (with source URLs) "
        "3. Critical CVEs Table (ID, CVSS Score, Description, NVD Link) "
        "4. Mitigation Recommendations (grouped by urgency) "
        "5. Conclusion. "
        "Use proper markdown formatting with headers, tables, and bullet points."
    ),
    expected_output=(
        "A complete markdown-formatted cybersecurity intelligence report with all 5 sections. "
        "CVEs must reference real IDs fetched by the vulnerability researcher."
    ),
    agent=cybersecurity_writer,
    context=[threat_analysis_task, vulnerability_research_task, incident_response_task],
)
