import sys
import os
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    current_file_path = Path(__file__).resolve()
    parent_dir = current_file_path.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))

    if Path.cwd().name == "linking_agent":
        os.chdir(parent_dir)

    from linking_agent.graph import graph
else:
    from .graph import graph


def run_linking_agent():
    print("=" * 60)
    print("  LINKING AGENT — Cybersecurity KG Entity Linking Pipeline")
    print("=" * 60)

    instruction = (
        "Identifikasi dan bangun relasi antarsumber cybersecurity "
        "(CVE→CWE→CAPEC→ATT&CK) menggunakan properti ontologi SEPSES. "
        "Baca output dari parser_agent dan data dari fetcher_agent."
    )
    print(f"\nInstruksi: {instruction}\n")

    result = graph.invoke({
        "messages":       [{"role": "user", "content": instruction}],
        "link_plan":      [],
        "current_task":   {},
        "linked_results": [],
        "all_done":       False,
    })

    print("\n" + "=" * 60)
    print("  HASIL AKHIR LINKING")
    print("=" * 60)

    linked_results = result.get("linked_results", [])
    success = [r for r in linked_results if r.get("status") == "success"]
    failed = [r for r in linked_results if r.get("status") != "success"]

    for r in linked_results:
        icon = "✓" if r.get("status") == "success" else "✗"
        print(f"\n{icon} {r['link_type'].upper()}")
        print(f"   Predicate : {r.get('predicate', '-')}")
        print(f"   Status    : {r['status']}")
        print(f"   Triples   : {r.get('triples_count', 0)}")
        if r.get("output_file"):
            print(f"   Output    : {r['output_file']}")
        if r.get("error"):
            print(f"   Error     : {r['error']}")

    print(f"\n{'─' * 60}")
    print(f"Berhasil : {len(success)} tugas linking")
    print(f"Gagal    : {len(failed)} tugas linking")
    total_triples = sum(r.get("triples_count", 0) for r in linked_results)
    print(f"Total Triple : {total_triples:,}")

    if result.get("messages"):
        print(f"\nRingkasan: {result['messages'][-1].content}")


if __name__ == "__main__":
    run_linking_agent()
