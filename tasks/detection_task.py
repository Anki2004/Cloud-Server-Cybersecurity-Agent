from crewai import Task
from agents.detection_agent import detection_agent

detection_task = Task(
    description=(
        "You must run ALL THREE monitoring tools before responding. Do not skip any.\n\n"
        "Step 1 — Log Analysis: Use the 'System Log Analyzer' tool with input "
        "'/var/log/auth.log,/var/log/syslog' to detect authentication attacks, "
        "privilege escalation, and malware processes.\n\n"
        "Step 2 — Network Monitoring: Use the 'Network Traffic Monitor' tool with "
        "input 'scan' to detect port scans, C2 beaconing, and backdoor ports.\n\n"
        "Step 3 — File System Scan: Use the 'File System Monitor' tool with input "
        "'24' to scan the last 24 hours for web shells, SUID binaries, modified "
        "system files, and unauthorized SSH key additions.\n\n"
        "Step 4 — Correlation: After running all three tools, correlate findings "
        "across sources. Flag any threat combinations that indicate a multi-stage "
        "attack (e.g. brute force + new SSH key = confirmed intrusion).\n\n"
        "Step 5 — Produce a unified detection report with: total threats found per "
        "source, severity breakdown (CRITICAL/HIGH/MEDIUM/LOW), correlated attack "
        "chains, and the top 3 most urgent findings."
    ),
    expected_output=(
        "A structured detection report with sections: "
        "1) Log Analysis Findings, "
        "2) Network Monitoring Findings, "
        "3) File System Findings, "
        "4) Correlated Attack Chains, "
        "5) Top 3 Most Urgent Threats. "
        "Each finding must include threat type, severity, source, and detail. "
        "If no threats are found in a category, explicitly state 'No threats detected'."
    ),
    agent=detection_agent,
)
