from crewai import Task
from agents.incident_advisor import incident_response_advisor
from tasks.threat_tasks import threat_analysis_task
from tasks.vulnerability_tasks import vulnerability_research_task

incident_response_task = Task(
    description=(
        "Using the threat intelligence and CVE data gathered by the previous agents, "
        "produce a prioritized list of mitigation strategies. "
        "For each threat or CVE, provide: the recommended action, urgency level, "
        "and the team responsible (e.g. SOC, DevOps, IT Admin). "
        "Group recommendations by urgency: Immediate, Short-term, Long-term."
    ),
    expected_output=(
        "A prioritized mitigation plan grouped into Immediate, Short-term, and Long-term actions. "
        "Each action should reference the specific threat or CVE it addresses."
    ),
    agent=incident_response_advisor,
    context=[threat_analysis_task, vulnerability_research_task],
)
