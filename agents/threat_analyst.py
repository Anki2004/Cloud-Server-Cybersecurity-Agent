import os
from dotenv import load_dotenv
load_dotenv()

from crewai import Agent, LLM
from tools.exa_tools import cybersecurity_threats_tool
from config import GROQ_API_KEY, MODEL_NAME

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = LLM(
    model=f"groq/{MODEL_NAME}",
    api_key=GROQ_API_KEY,
    temperature=0,
)

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
    tools=[cybersecurity_threats_tool],
    max_iter=5,
)