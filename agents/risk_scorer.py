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

risk_scorer = Agent(
    role="Cybersecurity Risk Scorer",
    goal=(
        "Analyze the final threat report and assign a structured risk severity matrix "
        "to each identified threat and vulnerability."
    ),
    backstory=(
        "You are a risk assessment specialist who quantifies cybersecurity threats. "
        "You read threat intelligence reports and produce a clean, structured risk matrix "
        "with severity levels (Critical / High / Medium / Low), likelihood scores, "
        "and business impact ratings for each identified threat. "
        "Your output is always structured and consistent so it can be rendered in a dashboard."
    ),
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
)