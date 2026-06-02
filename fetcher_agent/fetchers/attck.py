# fetchers/attck.py
import requests
import json
from .base import BaseFetcher, CACHE_DIR

# URL download langsung — lebih stabil daripada lewat GitHub API
ATTCK_DIRECT_URLS = {
    "attck_enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "attck_ics":        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}

ATTCK_VERSION_URLS = {
    "attck_enterprise": "https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=enterprise-attack/enterprise-attack.json&per_page=1",
    "attck_ics":        "https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=ics-attack/ics-attack.json&per_page=1",
}

class ATTCKFetcher(BaseFetcher):

    def __init__(self, variant: str = "enterprise"):
        self.variant = variant
        key = f"attck_{variant}"
        super().__init__(key)

    def get_remote_version(self) -> str | None:
        try:
            url = ATTCK_VERSION_URLS[self.source_name]
            resp = requests.get(url, timeout=15)
            commits = resp.json()
            if isinstance(commits, list) and commits:
                # Pakai SHA commit terbaru sebagai "versi"
                return commits[0]["sha"][:7]
        except Exception as e:
            print(f"  [{self.source_name}] gagal cek versi: {e}")
        return None

    def fetch(self) -> list[dict]:
        url = ATTCK_DIRECT_URLS[self.source_name]
        print(f"  [{self.source_name}] Mengunduh dari: {url}")

        resp = requests.get(url, stream=True, timeout=120)
        resp.raise_for_status()

        file_path = CACHE_DIR / f"{self.source_name}.json"
        with open(file_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)

        print(f"  [{self.source_name}] Tersimpan: {file_path}")
        # Return sebagai satu record berisi path file
        return [{"source": self.source_name, "file": str(file_path)}]
    
    def run(self) -> dict:
        print(f"\n[{self.source_name.upper()}] Memulai...")

        if not self.needs_update():
            print(f"  [{self.source_name}] Sudah up-to-date, pakai cache.")
            file_path = CACHE_DIR / f"{self.source_name}.json"
            # Hitung records dari file yang ada
            with open(file_path) as f:
                raw = json.load(f)
            records = len(raw.get("objects", [])) if isinstance(raw, dict) else 0
            return {
                "source": self.source_name,
                "status": "cached",
                "records": records,
                "file_path": str(file_path),
                "error": None,
            }

        try:
            self.fetch()  # fetch() sudah handle simpan file sendiri
            
            # Hitung jumlah attack-pattern objects
            file_path = CACHE_DIR / f"{self.source_name}.json"
            with open(file_path) as f:
                raw = json.load(f)
            records = len([o for o in raw.get("objects", []) if o.get("type") == "attack-pattern"])

            version = self.get_remote_version()
            if version:
                self.save_local_version(version)

            return {
                "source": self.source_name,
                "status": "success",
                "records": records,
                "file_path": str(file_path),
                "error": None,
            }
        except Exception as e:
            return {
                "source": self.source_name,
                "status": "failed",
                "records": 0,
                "file_path": "",
                "error": str(e),
            }