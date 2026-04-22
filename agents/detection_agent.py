from crewai import Agent
from langchain_groq import ChatGroq
from tools.log_analysis_tool import LogAnalysisTool
from tools.network_monitor_tool import NetworkMonitorTool
from tools.filesystem_monitor_tool import FileSystemMonitorTool
from config import GROQ_API_KEY, MODEL_NAME
import os

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = ChatGroq(temperature=0, model_name=MODEL_NAME)

detection_agent = Agent(
    role="Cloud Security Detection Agent",
    goal=(
        "Monitor the cloud server across all three attack surfaces — "
        "system logs, network traffic, and file system — to detect "
        "active threats and anomalies. Correlate findings across all "
        "three sources and produce a unified detection report."
    ),
    backstory=(
        "You are a senior SOC analyst specialized in cloud server forensics "
        "and intrusion detection. You have deep expertise in log analysis, "
        "network traffic anomaly detection, and post-exploitation forensics. "
        "You always run ALL three monitoring tools before drawing conclusions. "
        "You correlate findings across sources — for example, a brute force "
        "attempt in logs combined with a new SSH key in the filesystem is far "
        "more serious than either finding alone. You never skip a tool."
    ),
    tools=[
        LogAnalysisTool(),
        NetworkMonitorTool(),
        FileSystemMonitorTool(),
    ],
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=8,
    memory=True,
)
