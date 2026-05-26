from fetchers.nvd import CVEFetcher, CPEFetcher
from fetchers.mitre import CWEFetcher, CAPECFetcher
from fetchers.attck import ATTCKFetcher
from fetchers.icsa import ICSAFetcher

FETCHER_REGISTRY = {
    "cve":              CVEFetcher,
    "cpe":              CPEFetcher,
    "cwe":              CWEFetcher,
    "capec":            CAPECFetcher,
    "attck_enterprise": lambda: ATTCKFetcher("enterprise"),
    "attck_ics":        lambda: ATTCKFetcher("ics"),
    "icsa":             ICSAFetcher,
}

SOURCE_DESCRIPTIONS = {
    "cve":              "Kerentanan publik yang diketahui (diupdate tiap 2 jam)",
    "cpe":              "Nama standar produk & vendor IT",
    "cwe":              "Katalog kelemahan software umum",
    "capec":            "Katalog pola serangan",
    "attck_enterprise": "MITRE ATT&CK taktik & teknik (Enterprise)",
    "attck_ics":        "MITRE ATT&CK taktik & teknik (ICS/OT)",
    "icsa":             "CISA Known Exploited Vulnerabilities advisories",
}
