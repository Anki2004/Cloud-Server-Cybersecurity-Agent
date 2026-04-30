
from dotenv import load_dotenv

load_dotenv()
import os
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "outputs")

# Ensure outputs directory exists
os.makedirs(OUTPUTS_DIR, exist_ok=True)
os.environ["OPENAI_API_KEY"] = "sk-fake-not-used"