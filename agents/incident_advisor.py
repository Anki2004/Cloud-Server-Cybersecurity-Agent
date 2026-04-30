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
)