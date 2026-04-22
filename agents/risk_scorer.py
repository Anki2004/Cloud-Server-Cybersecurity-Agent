from crewai import Agent
from langchain_groq import ChatGroq
from config import GROQ_API_KEY, MODEL_NAME
import os

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

llm = ChatGroq(temperature=0, model_name=MODEL_NAME)

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
    memory=True,
)
