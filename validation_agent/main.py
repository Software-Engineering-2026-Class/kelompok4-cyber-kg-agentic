import sys
import os
from pathlib import Path

# =====================================================================
# PACKAGE PATH RESOLUTION SHIM
# =====================================================================
# Memastikan import paket validation_agent berjalan lancar baik saat
# dieksekusi dari direktori proyek root maupun dari dalam folder agen.
if __name__ == "__main__" and __package__ is None:
    current_file_path = Path(__file__).resolve()
    parent_dir = current_file_path.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))

    if Path.cwd().name == "validation_agent":
        os.chdir(parent_dir)

    from validation_agent.graph import graph
else:
    from .graph import graph


def run_validation_agent():
    """
    Eksekusi utama Validation Agent CLI.
    """
    print("=" * 65)
    print("  VALIDATION AGENT — Cybersecurity KG Quality Assurance Pipeline")
    print("=" * 65)

    instruction = (
        "Validasi keselarasan skema ontologi SEPSES, deteksi ketiadaan "
        "triple wajib (missing mandatory triples), dan laporkan anomali "
        "semantik pada grafik Turtle (.ttl) hasil output pipeline."
    )
    print(f"\nInstruksi: {instruction}\n")

    # Jalankan LangGraph Workflow secara sinkron
    result = graph.invoke({
        "messages":           [{"role": "user", "content": instruction}],
        "validation_plan":    [],
        "current_task":       {},
        "validation_results": [],
        "all_done":           False,
    })

    print("\n" + "=" * 65)
    print("  RINGKASAN VALIDASI KUALITAS SEMANTIK (MUTU AKHIR)")
    print("=" * 65)

    validation_results = result.get("validation_results", [])
    success = [r for r in validation_results if r.get("status") == "success"]
    failed = [r for r in validation_results if r.get("status") != "success"]

    # Render hasil di CLI dengan ikon yang representatif
    for r in validation_results:
        icon = "✓" if r.get("status") == "success" else "✗"
        print(f"\n{icon} {r['file_name'].upper()}")
        print(f"   Jalur Berkas : {r.get('file_path')}")
        print(f"   Status Parse : {r['status'].upper()}")
        print(f"   Total Triple : {r.get('total_triples', 0):,}")
        print(f"   Total Subjek : {r.get('validated_subjects', 0):,}")
        print(f"   Jumlah Error : {r.get('errors_count', 0) + r.get('critical_errors_count', 0)}")
        print(f"   Jml Warning  : {r.get('warnings_count', 0)}")
        
        if r.get("error_detail"):
            print(f"   Detail Error : {r['error_detail']}")

    print(f"\n{'─' * 65}")
    print(f"Grafik Sukses Diuji : {len(success)} berkas")
    print(f"Grafik Gagal Diuji  : {len(failed)} berkas")
    
    total_errors = sum((r.get("errors_count", 0) + r.get("critical_errors_count", 0)) for r in validation_results)
    total_warnings = sum(r.get("warnings_count", 0) for r in validation_results)
    print(f"Total Temuan Masalah: {total_errors} Error, {total_warnings} Warning")

    if result.get("messages"):
        print(f"\nPesan Akhir Agen: {result['messages'][-1].content}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_validation_agent()
