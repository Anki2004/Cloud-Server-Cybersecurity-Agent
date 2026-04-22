from crewai_tools import BaseTool
import requests
from logger import get_logger

logger = get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCVETool(BaseTool):
    name: str = "NVD CVE Fetcher"
    description: str = (
        "Fetches the latest real CVEs (Common Vulnerabilities and Exposures) "
        "from the National Vulnerability Database (NVD). "
        "Input should be a keyword string like 'ransomware' or 'apache'."
    )

    def _run(self, keyword: str) -> list:
        logger.info(f"Fetching CVEs from NVD for keyword: {keyword}")
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 5,
                "sortBy": "published",
                "sortOrder": "desc",
            }
            response = requests.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                descriptions = cve.get("descriptions", [])
                description_text = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description available"
                )

                # Extract CVSS score safely
                metrics = cve.get("metrics", {})
                cvss_score = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                cves.append({
                    "id": cve.get("id", "Unknown"),
                    "published": cve.get("published", "Unknown"),
                    "description": description_text,
                    "cvss_score": cvss_score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                })

            logger.info(f"Fetched {len(cves)} CVEs from NVD.")
            return cves

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            raise
