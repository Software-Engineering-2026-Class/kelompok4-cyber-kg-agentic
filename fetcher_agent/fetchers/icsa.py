import requests
from .base import BaseFetcher

class ICSAFetcher(BaseFetcher):

    def __init__(self):
        super().__init__("icsa")
        self.feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(self.feed_url, timeout=15)
            return resp.json().get("dateUpdated")
        except Exception as e:
            print(f"  [icsa] gagal cek versi remote: {e}")
        return None

    def fetch(self) -> list[dict]:
        print(f"  [icsa] Mengunduh dari: {self.feed_url}")
        resp = requests.get(self.feed_url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"  [icsa] {len(vulnerabilities)} advisories ditemukan")
        return vulnerabilities
