"""Download data from NVD, CISA KEV and FIRST EPSS, politely: wait between calls, retry when busy."""

import time
from urllib.parse import quote

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "CallGuard (GEN ACADEMY RAG course project)"


def keyword_query(keyword, exact=False):
    """NVD query text for CVEs whose description mentions a keyword (rejected CVEs left out)."""
    query = f"keywordSearch={quote(keyword)}&noRejected"
    return query + "&keywordExactMatch" if exact else query


def changed_query(start, end):
    """NVD query text for every CVE changed between two UTC times (at most 120 days apart).
    Rejected CVEs are included on purpose, so a sync can remove them."""
    def stamp(t):
        return quote(t.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"))
    return f"lastModStartDate={stamp(start)}&lastModEndDate={stamp(end)}"


class Sources:
    def __init__(self, nvd_api_key=None):
        self.http = httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": USER_AGENT})
        self.nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
        # NVD allows 5 requests per 30 seconds without a key and 50 with one
        self.nvd_gap = 0.7 if nvd_api_key else 6.5
        self.last_nvd_call = 0.0

    def get_json(self, url, params=None, headers=None, tries=4):
        """GET a URL and return its JSON, retrying with longer waits if the service is busy."""
        for attempt in range(1, tries + 1):
            try:
                r = self.http.get(url, params=params, headers=headers)
                if r.status_code == 200:
                    return r.json()
                problem = f"HTTP {r.status_code} {r.headers.get('message', '')}".strip()
            except httpx.HTTPError as e:
                problem = f"{type(e).__name__}: {e}"
            if attempt == tries:
                raise RuntimeError(f"{url} failed after {tries} tries: {problem}")
            time.sleep(10 * attempt)  # like redialing after a busy signal, waiting longer each time

    def nvd_pages(self, query):
        """Yield NVD result pages (up to 2,000 CVEs each) until every match has been fetched."""
        start, total = 0, None
        while total is None or start < total:
            wait = self.nvd_gap - (time.time() - self.last_nvd_call)
            if wait > 0:
                time.sleep(wait)
            page = self.get_json(f"{NVD_URL}?{query}&resultsPerPage=2000&startIndex={start}",
                                 headers=self.nvd_headers)
            self.last_nvd_call = time.time()
            total = page["totalResults"]
            yield start, total, page
            if not page["vulnerabilities"]:
                break
            start += len(page["vulnerabilities"])

    def kev_catalog(self):
        return self.get_json(KEV_URL)

    def epss_scores(self, cve_ids, batch=100):
        """Return {cve_id: {"score", "percentile", "date"}} for the CVEs EPSS has scored."""
        ids, scores = sorted(cve_ids), {}
        for i in range(0, len(ids), batch):
            data = self.get_json(EPSS_URL, params={"cve": ",".join(ids[i:i + batch]), "limit": batch})
            for row in data["data"]:
                scores[row["cve"]] = {"score": float(row["epss"]), "percentile": float(row["percentile"]),
                                      "date": row["date"]}
        return scores
