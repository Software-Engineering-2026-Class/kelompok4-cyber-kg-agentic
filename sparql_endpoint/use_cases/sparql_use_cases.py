"""
sparql_use_cases.py — Security-Related SPARQL Use Cases
SEPSES Cybersecurity Knowledge Graph — Kelompok 4

Use Case 1: Vulnerability Attack Chain Analysis
  Skenario: SOC analyst ingin menelusuri rantai serangan dari suatu CVE —
  dari kelemahan (CWE) → pola serangan (CAPEC) → teknik ATT&CK.
  Relevansi: Membantu threat hunting dan pembuatan detection rule.

Use Case 2: Exploited Vulnerability Prioritization
  Skenario: Tim keamanan ingin memprioritaskan patch dengan mencari CVE
  yang sudah aktif dieksploitasi (ada di ICSA/KEV) beserta produk terdampak.
  Relevansi: Membantu patch management dan risk prioritization.

Use Case 3: ATT&CK Technique Coverage Mapping
  Skenario: Red team ingin mengetahui teknik ATT&CK mana yang paling banyak
  dipetakan ke pola serangan CAPEC, untuk menentukan prioritas simulasi.
  Relevansi: Membantu purple team exercise dan adversary emulation planning.
"""

import requests
import json
from datetime import datetime

SPARQL_ENDPOINT = "http://localhost:8890/sparql"

def run_query(sparql: str) -> list[dict]:
    resp = requests.get(
        SPARQL_ENDPOINT,
        params={"query": sparql, "format": "application/sparql-results+json"},
        timeout=30
    )
    resp.raise_for_status()
    bindings = resp.json()["results"]["bindings"]
    return [{k: v["value"] for k, v in row.items()} for row in bindings]

def print_table(rows: list[dict], max_rows: int = 10):
    if not rows:
        print("  (tidak ada hasil)")
        return
    headers = list(rows[0].keys())
    col_widths = {h: max(len(h), max(len(str(r.get(h, ""))[:50]) for r in rows[:max_rows])) for h in headers}
    separator = "+-" + "-+-".join("-" * col_widths[h] for h in headers) + "-+"
    header_row = "| " + " | ".join(h.ljust(col_widths[h]) for h in headers) + " |"
    print(f"  {separator}")
    print(f"  {header_row}")
    print(f"  {separator}")
    for row in rows[:max_rows]:
        line = "| " + " | ".join(str(row.get(h, ""))[:50].ljust(col_widths[h]) for h in headers) + " |"
        print(f"  {line}")
    print(f"  {separator}")
    if len(rows) > max_rows:
        print(f"  ... dan {len(rows) - max_rows} hasil lainnya")

# ─────────────────────────────────────────────────────────────
# USE CASE 1: Vulnerability Attack Chain Analysis
# ─────────────────────────────────────────────────────────────
UC1_QUERY = """
PREFIX cve:   <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe:   <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attck: <http://w3id.org/sepses/vocab/ref/attack#>

SELECT DISTINCT ?cveId ?cweName ?capecId ?attckTechnique
WHERE {
  GRAPH <http://w3id.org/sepses/graph/cve_to_cwe> {
    ?cve cve:hasCWE ?cweNode .
  }
  GRAPH <http://w3id.org/sepses/graph/cve> {
    ?cve cve:id ?cveId .
  }
  GRAPH <http://w3id.org/sepses/graph/cwe> {
    ?cweNode cwe:name ?cweName .
  }
  GRAPH <http://w3id.org/sepses/graph/cwe_to_capec> {
    ?cweNode cwe:hasCAPEC ?capecNode .
  }
  GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
    ?capecNode capec:hasRelatedAttackPattern ?attckNode .
    BIND(STRAFTER(STR(?capecNode), "capec/") AS ?capecId)
    BIND(STRAFTER(STR(?attckNode), "attack/") AS ?attckTechnique)
  }
}
ORDER BY ?cveId
LIMIT 20
"""

# ─────────────────────────────────────────────────────────────
# USE CASE 2: Exploited Vulnerability Prioritization
# ─────────────────────────────────────────────────────────────
UC2_QUERY = """
PREFIX cve:  <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX icsa: <http://w3id.org/sepses/vocab/ref/icsa#>
PREFIX cwe:  <http://w3id.org/sepses/vocab/ref/cwe#>

SELECT DISTINCT ?cveId ?vendor ?product
(COUNT(DISTINCT ?icsaNode) AS ?exploitCount)
WHERE {
  GRAPH <http://w3id.org/sepses/graph/icsa> {
    ?icsaNode a icsa:ICSA ;
              icsa:cveID ?cveId ;
              icsa:vendorProject ?vendor ;
              icsa:product ?product .
  }
}
GROUP BY ?cveId ?vendor ?product
ORDER BY DESC(?exploitCount) ?vendor
LIMIT 20
"""

# ─────────────────────────────────────────────────────────────
# USE CASE 3: ATT&CK Technique Coverage Mapping
# ─────────────────────────────────────────────────────────────
UC3_QUERY = """
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attck: <http://w3id.org/sepses/vocab/ref/attack#>

SELECT ?techniqueId ?techniqueName ?techniqueDesc
       (COUNT(DISTINCT ?capecNode) AS ?capecCount)
WHERE {
  GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
    ?capecNode capec:hasRelatedAttackPattern ?attckNode .
  }
  GRAPH <http://w3id.org/sepses/graph/attck_enterprise> {
    ?attckNode attck:techniqueId ?techniqueId .
    ?attckNode attck:name ?techniqueName .
    OPTIONAL { ?attckNode attck:description ?techniqueDesc . }
  }
}
GROUP BY ?techniqueId ?techniqueName ?techniqueDesc
ORDER BY DESC(?capecCount)
LIMIT 15
"""

# ─────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  SPARQL SECURITY USE CASES — SEPSES Cyber-KG")
    print("=" * 70)

    # ── USE CASE 1 ──────────────────────────────────────────
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  USE CASE 1: Vulnerability Attack Chain Analysis                     ║
╚══════════════════════════════════════════════════════════════════════╝

SKENARIO:
  Seorang SOC analyst mendeteksi aktivitas mencurigakan dan ingin
  menelusuri rantai serangan lengkap dari suatu CVE — mulai dari
  kelemahan software (CWE), pola serangan yang digunakan (CAPEC),
  hingga teknik ATT&CK yang relevan untuk deteksi di SIEM.

QUERY:""")
    print(UC1_QUERY)

    print("HASIL:")
    try:
        results1 = run_query(UC1_QUERY)
        print_table(results1)
        print(f"\n  Total: {len(results1)} attack chains ditemukan")
    except Exception as e:
        print(f"  Error: {e}")

    print("""
PENJELASAN KEAMANAN:
  Query ini menelusuri rantai serangan multi-layer:
  CVE → CWE → CAPEC → ATT&CK
  Hasilnya membantu analyst memahami BAGAIMANA suatu kerentanan dapat
  dieksploitasi dalam konteks teknik serangan nyata, sehingga dapat
  membuat detection rules yang lebih tepat sasaran di SIEM/EDR.
""")

    # ── USE CASE 2 ──────────────────────────────────────────
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  USE CASE 2: Exploited Vulnerability Prioritization                  ║
╚══════════════════════════════════════════════════════════════════════╝

SKENARIO:
  Tim vulnerability management perlu memprioritaskan patch dari ratusan
  CVE yang ada. Dengan menggabungkan data CISA Known Exploited
  Vulnerabilities (KEV/ICSA) dengan informasi vendor, produk, dan
  jenis kelemahan, mereka dapat fokus pada CVE yang paling kritis
  dan sudah terbukti dieksploitasi di lapangan.

QUERY:""")
    print(UC2_QUERY)

    print("HASIL:")
    try:
        results2 = run_query(UC2_QUERY)
        print_table(results2)
        print(f"\n  Total: {len(results2)} exploited vulnerabilities ditemukan")
    except Exception as e:
        print(f"  Error: {e}")

    print("""
PENJELASAN KEAMANAN:
  CISA KEV adalah daftar CVE yang sudah terbukti dieksploitasi secara
  aktif. Query ini menggabungkan KEV dengan informasi vendor/produk dan
  jenis kelemahan (CWE), menghasilkan daftar prioritas patch yang
  actionable. CVE dengan kelemahan berbahaya (misal CWE-78 Command
  Injection) pada vendor besar harus ditangani segera.
""")

    # ── USE CASE 3 ──────────────────────────────────────────
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  USE CASE 3: ATT&CK Technique Coverage Mapping                       ║
╚══════════════════════════════════════════════════════════════════════╝

SKENARIO:
  Tim red team ingin mengetahui teknik ATT&CK mana yang paling banyak
  dipetakan ke pola serangan CAPEC, untuk menentukan prioritas simulasi
  adversary dan memastikan coverage deteksi yang memadai.
  Teknik dengan banyak CAPEC mapping berarti banyak cara berbeda
  untuk mengeksekusi teknik tersebut — lebih sulit dideteksi.

QUERY:""")
    print(UC3_QUERY)

    print("HASIL:")
    try:
        results3 = run_query(UC3_QUERY)
        # Truncate description untuk display
        for r in results3:
            if "techniqueDesc" in r:
                r["techniqueDesc"] = r["techniqueDesc"][:60] + "..." if len(r.get("techniqueDesc","")) > 60 else r.get("techniqueDesc","")
        print_table(results3)
        print(f"\n  Total: {len(results3)} teknik ATT&CK teratas ditampilkan")
    except Exception as e:
        print(f"  Error: {e}")

    print("""
PENJELASAN KEAMANAN:
  Teknik ATT&CK dengan jumlah CAPEC mapping terbanyak mengindikasikan
  teknik yang memiliki banyak variasi eksekusi. Red team dapat
  memprioritaskan simulasi teknik ini untuk menguji coverage deteksi,
  sementara blue team dapat menggunakannya untuk memperkuat rule
  deteksi di SIEM berdasarkan pola CAPEC yang dipetakan.
""")

    print("=" * 70)
    print(f"  Selesai: {datetime.now().strftime('%d %B %Y, %H:%M')}")
    print(f"  Endpoint: {SPARQL_ENDPOINT}")
    print("=" * 70)

if __name__ == "__main__":
    main()