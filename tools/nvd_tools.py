from crewai.tools import tool
import requests
from logger import get_logger

logger = get_logger(__name__)
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@tool("NVD CVE Fetcher")
def nvd_cve_tool(keyword: str) -> list:
    """Fetches the latest real CVEs from the National Vulnerability Database (NVD).
    Input should be a keyword string like 'ransomware' or 'apache'."""

    logger.info(f"Fetching CVEs for: {keyword}")
    params = {"keywordSearch": keyword, "resultsPerPage": 5, "sortBy": "published", "sortOrder": "desc"}
    response = requests.get(NVD_BASE_URL, params=params, timeout=10)
    response.raise_for_status()
    data = response.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
        metrics = cve.get("metrics", {})
        cvss = "N/A"
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        cves.append({
            "id": cve.get("id", "Unknown"),
            "published": cve.get("published", "Unknown"),
            "description": desc,
            "cvss_score": cvss,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
        })
    return cves