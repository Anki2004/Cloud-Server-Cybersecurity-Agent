from crewai import Agent
from langchain_groq import ChatGroq
from tools.exa_tools import CybersecurityThreatsTool
from config import GROQ_API_KEY, MODEL_NAME
import os

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = ChatGroq(temperature=0, model_name=MODEL_NAME)

threat_analyst = Agent(
    role="Cybersecurity Threat Intelligence Analyst",
    goal="Gather real-time cybersecurity threat intelligence using available tools.",
    backstory=(
        "You're an expert in cybersecurity, tracking emerging threats, malware campaigns, "
        "and hacking incidents. You always use your tools to fetch real data before answering "
        "and never rely on your training knowledge for current threat information."
    ),
    verbose=True,
    allow_delegation=False,
    llm=llm,
    tools=[CybersecurityThreatsTool()],
    max_iter=5,
    memory=True,
)
