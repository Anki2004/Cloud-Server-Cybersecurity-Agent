from crewai import Agent
from langchain_groq import ChatGroq
from config import GROQ_API_KEY, MODEL_NAME
import os

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = ChatGroq(temperature=0, model_name=MODEL_NAME)

incident_response_advisor = Agent(
    role="Incident Response Advisor",
    goal="Provide actionable mitigation strategies for detected threats and vulnerabilities.",
    backstory=(
        "You specialize in cybersecurity defense strategies, helping organizations respond "
        "to security incidents effectively. You synthesize threat and vulnerability data from "
        "other agents and produce concrete, prioritized defensive recommendations."
    ),
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
    memory=True,
)
