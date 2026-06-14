"""
load.py — Load semua TTL ke Virtuoso via isql bulk loader
"""

import subprocess
import requests
from pathlib import Path

import os
VIRTUOSO_HOST = os.environ.get("VIRTUOSO_HOST", "localhost")
VIRTUOSO_SPARQL = f"http://{VIRTUOSO_HOST}:8890/sparql"
GRAPH_BASE = "http://w3id.org/sepses/graph/"
TOLOAD_DIR = Path(__file__).parent / "toload"
CONTAINER_NAME = os.environ.get("VIRTUOSO_CONTAINER", "cskg-sparql")


def run_isql(command: str) -> tuple[bool, str]:
    """Jalankan command via isql di dalam container Virtuoso."""
    result = subprocess.run(
        [
            "docker",
            "exec",
            CONTAINER_NAME,
            "isql",
            "1111",
            "dba",
            "dba",
            f"EXEC={command}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = result.stdout + result.stderr
    return result.returncode, output


def load_ttl_via_isql(ttl_file: Path, graph_uri: str) -> bool:
    """Load satu file TTL ke named graph via isql LOAD command."""
    print(f"  Loading {ttl_file.name} → <{graph_uri}>")

    command = f"SPARQL LOAD <file:///opt/virtuoso-opensource/vsp/toload/{ttl_file.name}> INTO GRAPH <{graph_uri}>;"
    returncode, output = run_isql(command)

    # isql return 0 = sukses, cek juga tidak ada error message
    if returncode == 0 and "*** Error" not in output:
        print(f"  ✓ Berhasil: {ttl_file.name}")
        return True
    else:
        # Filter banner koneksi, tampilkan hanya error-nya
        error_lines = [
            l
            for l in output.splitlines()
            if "***" in l or "Error" in l or "error" in l.lower()
        ]
        print(
            f"  ✗ Gagal: {chr(10).join(error_lines) if error_lines else output[:200]}"
        )
        return False


def verify_endpoint():
    """Test basic SPARQL query ke endpoint."""
    print("\n  Verifikasi endpoint...")
    query = "SELECT (COUNT(*) AS ?total) WHERE { ?s ?p ?o }"
    resp = requests.get(
        VIRTUOSO_SPARQL,
        params={"query": query, "format": "application/sparql-results+json"},
        timeout=30,
    )
    if resp.status_code == 200:
        data = resp.json()
        total = data["results"]["bindings"][0]["total"]["value"]
        print(f"  ✓ Endpoint OK — Total triple: {total}")
        return True
    else:
        print(f"  ✗ Endpoint error: {resp.status_code}")
        return False


def main():
    print("=" * 60)
    print("  SPARQL ENDPOINT LOADER — SEPSES Cyber-KG")
    print("=" * 60)

    ttl_files = sorted(TOLOAD_DIR.glob("*.ttl"))
    if not ttl_files:
        print("  ERROR: Tidak ada file .ttl di folder toload/")
        return

    print(f"\n  Ditemukan {len(ttl_files)} file TTL untuk dimuat.\n")

    success = 0
    failed = 0

    for ttl_file in ttl_files:
        graph_uri = GRAPH_BASE + ttl_file.stem
        result = load_ttl_via_isql(ttl_file, graph_uri)
        if result:
            success += 1
        else:
            failed += 1

    print(f"\n{'─' * 60}")
    print(f"  Berhasil : {success} file")
    print(f"  Gagal    : {failed} file")

    if success > 0:
        verify_endpoint()

    print(f"\n  SPARQL Endpoint : http://localhost:8890/sparql")
    print(f"  Web UI          : http://localhost:8890/conductor")
    print(f"  Named Graphs    : {GRAPH_BASE}*")
    print("=" * 60)


if __name__ == "__main__":
    main()
