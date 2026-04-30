import os
from dotenv import load_dotenv
load_dotenv()

from crewai import Agent, LLM
from tools.log_analysis_tool import log_analysis_tool
from tools.network_monitor_tool import network_monitor_tool
from tools.filesystem_monitor_tool import filesystem_monitor_tool
from config import GROQ_API_KEY, MODEL_NAME

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = LLM(
    model=f"groq/{MODEL_NAME}",
    api_key=GROQ_API_KEY,
    temperature=0,
)

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
    tools=[log_analysis_tool, network_monitor_tool, filesystem_monitor_tool],
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=8,
)