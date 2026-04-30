import os
from dotenv import load_dotenv
load_dotenv()

from crewai import Agent, LLM
from config import GROQ_API_KEY, MODEL_NAME

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = LLM(
    model=f"groq/{MODEL_NAME}",
    api_key=GROQ_API_KEY,
    temperature=0,
)

cybersecurity_writer = Agent(
    role="Cybersecurity Report Writer",
    goal="Generate a structured, executive-level cybersecurity threat report.",
    backstory=(
        "You're a leading cybersecurity analyst with years of experience writing security reports "
        "for executive and technical audiences. You synthesize all gathered intelligence into a "
        "clear, well-structured markdown report with an executive summary, threat breakdown, "
        "CVE table, and prioritized recommendations."
    ),
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
)