import requests
import zipfile
import re
from pathlib import Path
from .base import BaseFetcher, CACHE_DIR


class CWEFetcher(BaseFetcher):

    def __init__(self):
        super().__init__("cwe")
        self.download_page = "https://cwe.mitre.org/data/downloads.html"
        self.base_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(self.download_page, timeout=15)
            match = re.search(r'cwec_v([\d.]+)\.xml', resp.text)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"  [cwe] gagal cek versi remote: {e}")
        return None

    def fetch(self) -> list[dict]:
        zip_path = CACHE_DIR / "cwe.zip"

        print(f"  [cwe] Mengunduh dari: {self.base_url}")
        resp = requests.get(self.base_url, stream=True, timeout=60)
        resp.raise_for_status()

        with open(zip_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)

        with zipfile.ZipFile(zip_path, "r") as z:
            xml_files = [n for n in z.namelist() if n.endswith(".xml")]
            if not xml_files:
                raise ValueError("Tidak ada file XML di dalam zip CWE")
            xml_file = xml_files[0]
            z.extract(xml_file, CACHE_DIR)
            extracted_path = CACHE_DIR / xml_file

        print(f"  [cwe] File XML tersimpan: {extracted_path}")
        return [{"source": "cwe", "file": str(extracted_path)}]


class CAPECFetcher(BaseFetcher):

    def __init__(self):
        super().__init__("capec")
        self.download_page = "https://capec.mitre.org/data/downloads.html"
        self.base_url = "https://capec.mitre.org/data/xml/capec_latest.xml"

    def get_remote_version(self) -> str | None:
        try:
            resp = requests.get(self.download_page, timeout=15)
            match = re.search(r'capec_v([\d.]+)\.xml', resp.text)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"  [capec] gagal cek versi remote: {e}")
        return None

    def fetch(self) -> list[dict]:
        xml_path = CACHE_DIR / "capec.xml"

        print(f"  [capec] Mengunduh dari: {self.base_url}")
        resp = requests.get(self.base_url, stream=True, timeout=60)
        resp.raise_for_status()

        with open(xml_path, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)

        print(f"  [capec] File XML tersimpan: {xml_path}")
        return [{"source": "capec", "file": str(xml_path)}]
