import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "llama3-70b-8192")
OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "outputs")

# Ensure outputs directory exists
os.makedirs(OUTPUTS_DIR, exist_ok=True)
