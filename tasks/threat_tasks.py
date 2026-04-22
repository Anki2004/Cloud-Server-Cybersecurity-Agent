from crewai import Task
from agents.threat_analyst import threat_analyst

threat_analysis_task = Task(
    description=(
        "You have been given a detection report from the Cloud Security Detection Agent "
        "identifying active threats on the monitored cloud server. "
        "Use the 'Cybersecurity Threats Fetcher' tool to search for real-time intelligence "
        "on the specific threat types detected (e.g. if brute force SSH was detected, search "
        "'latest SSH brute force attack campaigns 2024'). "
        "Also do a general search for 'latest cybersecurity threats 2024'. "
        "Return a structured list of the top threats including title, source URL, "
        "published date, and a brief summary. "
        "Do NOT answer from memory — always use the tool."
    ),
    expected_output=(
        "A structured list of at least 5 recent cybersecurity threats relevant to the "
        "detected threats, with title, URL, published date, and summary for each."
    ),
    agent=threat_analyst,
)
