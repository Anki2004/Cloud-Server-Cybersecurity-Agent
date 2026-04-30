from crewai.tools import tool
from exa_py import Exa
from config import EXA_API_KEY
from logger import get_logger

logger = get_logger(__name__)
exa_client = Exa(api_key=EXA_API_KEY)


@tool("Cybersecurity Threats Fetcher")
def cybersecurity_threats_tool(query: str) -> list:
    """Fetches latest real-time cybersecurity threats, malware campaigns,
    and hacking incidents using the Exa search API.
    Input should be a search query like 'latest cybersecurity threats 2024'."""

    logger.info(f"Fetching threats for: {query}")
    result = exa_client.search_and_contents(query, summary=True)
    if not result.results:
        return []
    return [{
        "title": getattr(item, "title", "No Title"),
        "url": getattr(item, "url", "#"),
        "published_date": getattr(item, "published_date", "Unknown"),
        "summary": getattr(item, "summary", "No Summary"),
    } for item in result.results]