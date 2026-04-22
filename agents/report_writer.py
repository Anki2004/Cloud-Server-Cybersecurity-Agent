from crewai import Agent
from langchain_groq import ChatGroq
from config import GROQ_API_KEY, MODEL_NAME
import os

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = ChatGroq(temperature=0, model_name=MODEL_NAME)

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
    memory=True,
)
