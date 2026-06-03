"""
verify.py — Verifikasi SPARQL endpoint SEPSES Cyber-KG
"""

import requests

import os
VIRTUOSO_HOST = os.environ.get("VIRTUOSO_HOST", "localhost")
SPARQL_ENDPOINT = f"http://{VIRTUOSO_HOST}:8890/sparql"


def query(sparql: str, description: str) -> bool:
    print(f"\n  [{description}]")
    print(f"  Query: {sparql[:80]}...")
    resp = requests.get(
        SPARQL_ENDPOINT,
        params={"query": sparql, "format": "application/sparql-results+json"},
        timeout=30,
    )
    if resp.status_code != 200:
        print(f"  ✗ Error: {resp.status_code}")
        return False

    bindings = resp.json()["results"]["bindings"]
    for row in bindings[:3]:
        print("  →", {k: v["value"] for k, v in row.items()})
    print(f"  ✓ {len(bindings)} hasil")
    return True


def main():
    print("=" * 60)
    print("  SPARQL ENDPOINT VERIFICATION — SEPSES Cyber-KG")
    print("=" * 60)

    tests = [
        (
            "SELECT (COUNT(*) AS ?total) WHERE { ?s ?p ?o }",
            "Total triple di seluruh graph",
        ),
        ("SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } }", "Daftar named graphs"),
        (
            """SELECT ?cve ?desc WHERE {
               GRAPH <http://w3id.org/sepses/graph/cve> {
                 ?cve a <http://w3id.org/sepses/vocab/ref/cve#CVE> ;
                      <http://w3id.org/sepses/vocab/ref/cve#id> ?desc .
               }
             } LIMIT 3""",
            "Sample CVE entries",
        ),
        (
            """SELECT ?cwe ?name WHERE {
               GRAPH <http://w3id.org/sepses/graph/cwe> {
                 ?cwe a <http://w3id.org/sepses/vocab/ref/cwe#CWE> ;
                      <http://w3id.org/sepses/vocab/ref/cwe#name> ?name .
               }
             } LIMIT 3""",
            "Sample CWE entries",
        ),
        (
            """SELECT ?capec ?attck WHERE {
               GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
                 ?capec <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> ?attck .
               }
             } LIMIT 3""",
            "Sample CAPEC → ATT&CK links",
        ),
        (
            """SELECT ?icsa ?cve WHERE {
               GRAPH <http://w3id.org/sepses/graph/icsa_to_cve> {
                 ?icsa <http://w3id.org/sepses/vocab/ref/icsa#hasCVE> ?cve .
               }
             } LIMIT 3""",
            "Sample ICSA → CVE links",
        ),
    ]

    passed = 0
    for sparql, desc in tests:
        if query(sparql, desc):
            passed += 1

    print(f"\n{'─' * 60}")
    print(f"  Tests passed: {passed}/{len(tests)}")
    print(f"\n  Endpoint URL : {SPARQL_ENDPOINT}")
    print(f"  Web UI       : http://localhost:8890/conductor")
    print("=" * 60)


if __name__ == "__main__":
    main()
