import os
import requests
import time
from dotenv import load_dotenv
from .base import BaseFetcher

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_DELAY = 0.6 if NVD_API_KEY else 6
PAGE_SIZE = 2000
MAX_DEMO = 1000

def _get_headers():
    if NVD_API_KEY:
        return {"apiKey": NVD_API_KEY}
    return {}

class CVEFetcher(BaseFetcher):

    def __init__(self):
        super().__init__("cve")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": 1},
                headers=_get_headers(),
                timeout=30
            )
            data = resp.json()
            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]["cve"]["lastModified"]
        except Exception as e:
            print(f"  [cve] gagal cek versi remote: {e}")
        return None

    def fetch(self) -> list[dict]:
        all_cves = []
        start_index = 0

        resp = requests.get(
            self.base_url,
            params={"resultsPerPage": 1, "startIndex": 0},
            headers=_get_headers(),
            timeout=30
        )
        try:
            total = resp.json().get("totalResults", 0)
        except Exception as e:
            print(f"  [cve] ERROR ambil total: {e}, status: {resp.status_code}")
            return []
        print(f"  [cve] Total CVE tersedia: {total:,}")
        print(f"  [cve] Demo mode: hanya ambil {MAX_DEMO} record pertama")
        time.sleep(NVD_DELAY)

        while len(all_cves) < MAX_DEMO:
            batch_size = min(PAGE_SIZE, MAX_DEMO - len(all_cves))
            print(f"  [cve] Halaman: record {start_index} - {start_index + batch_size}")
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": batch_size, "startIndex": start_index},
                headers=_get_headers(),
                timeout=60
            )
            try:
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"  [cve] ERROR: {e}, status: {resp.status_code}, body: {resp.text[:200]}")
                break
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            all_cves.extend(vulnerabilities)
            print(f"  [cve] Terkumpul: {len(all_cves)}")
            if len(all_cves) >= MAX_DEMO:
                break
            start_index += batch_size
            time.sleep(NVD_DELAY)

        return all_cves


class CPEFetcher(BaseFetcher):

    def __init__(self):
        super().__init__("cpe")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": 1},
                headers=_get_headers(),
                timeout=30
            )
            data = resp.json()
            if data.get("products"):
                return data["products"][0]["cpe"]["lastModified"]
        except Exception as e:
            print(f"  [cpe] gagal cek versi remote: {e}")
        return None

    def fetch(self) -> list[dict]:
        all_cpes = []
        start_index = 0

        resp = requests.get(
            self.base_url,
            params={"resultsPerPage": 1, "startIndex": 0},
            headers=_get_headers(),
            timeout=30
        )
        try:
            total = resp.json().get("totalResults", 0)
        except Exception as e:
            print(f"  [cpe] ERROR ambil total: {e}, status: {resp.status_code}")
            return []
        print(f"  [cpe] Total CPE tersedia: {total:,}")
        print(f"  [cpe] Demo mode: hanya ambil {MAX_DEMO} record pertama")
        time.sleep(NVD_DELAY)

        while len(all_cpes) < MAX_DEMO:
            batch_size = min(PAGE_SIZE, MAX_DEMO - len(all_cpes))
            print(f"  [cpe] Halaman: record {start_index} - {start_index + batch_size}")
            resp = requests.get(
                self.base_url,
                params={"resultsPerPage": batch_size, "startIndex": start_index},
                headers=_get_headers(),
                timeout=60
            )
            try:
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"  [cpe] ERROR: {e}, status: {resp.status_code}, body: {resp.text[:200]}")
                break
            products = data.get("products", [])
            if not products:
                break
            all_cpes.extend(products)
            print(f"  [cpe] Terkumpul: {len(all_cpes)}")
            if len(all_cpes) >= MAX_DEMO:
                break
            start_index += batch_size
            time.sleep(NVD_DELAY)

        return all_cpes