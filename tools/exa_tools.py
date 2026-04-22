from crewai_tools import BaseTool
from exa_py import Exa
from config import EXA_API_KEY
from logger import get_logger

logger = get_logger(__name__)

exa_client = Exa(api_key=EXA_API_KEY)


class CybersecurityThreatsTool(BaseTool):
    name: str = "Cybersecurity Threats Fetcher"
    description: str = (
        "Fetches the latest real-time cybersecurity threats, malware campaigns, "
        "and hacking incidents using the Exa search API. "
        "Input should be a search query string like 'latest cybersecurity threats 2024'."
    )

    def _run(self, query: str) -> list:
        logger.info(f"Fetching cybersecurity threats for query: {query}")
        try:
            result = exa_client.search_and_contents(query, summary=True)
            if not result.results:
                logger.warning("No results returned from Exa for threats query.")
                return []

            threats = []
            for item in result.results:
                threats.append({
                    "title": getattr(item, "title", "No Title"),
                    "url": getattr(item, "url", "#"),
                    "published_date": getattr(item, "published_date", "Unknown Date"),
                    "summary": getattr(item, "summary", "No Summary"),
                })

            logger.info(f"Fetched {len(threats)} threats from Exa.")
            return threats

        except Exception as e:
            logger.error(f"Exa API error in CybersecurityThreatsTool: {e}")
            raise
