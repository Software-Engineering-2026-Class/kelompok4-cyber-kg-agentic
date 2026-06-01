import os
from pathlib import Path
from ..state import ValidationState


def planner(state: ValidationState) -> ValidationState:
    """
    Node Planner: Menganalisis hasil keluaran linking_agent dan menyusun rencana validasi.
    """
    print("\n  [PLANNER] Memulai analisis output linking_agent...")

    linking_output_dir = Path("linking_agent/output")
    validation_plan = []

    # Format-format berkas Turtle yang diharapkan akan divalidasi
    expected_links = [
        "cve_to_cwe",
        "cve_to_cpe",
        "cwe_to_capec",
        "capec_to_attck",
        "icsa_to_cve"
    ]

    found_files = []

    # 1. Pindai direktori linking_agent/output
    if linking_output_dir.exists():
        for file in linking_output_dir.iterdir():
            if file.is_file() and file.suffix.lower() == ".ttl":
                found_files.append(file)
                print(f"  [PLANNER] Ditemukan berkas grafik Turtle: {file.name}")
    else:
        print("  [PLANNER] WARNING: Direktori linking_agent/output belum terbentuk.")

    # 2. Susun tugas validasi berdasarkan berkas yang ditemukan
    if found_files:
        for file_path in sorted(found_files):
            stem = file_path.stem.lower()
            task = {
                "file_name": file_path.name,
                "file_path": str(file_path),
                "link_type": stem,
                "description": f"Validasi semantik untuk grafik relasi {stem.upper()}"
            }
            validation_plan.append(task)
            print(f"  [PLANNER] ✓ Dijadwalkan: {file_path.name}")
    else:
        print("  [PLANNER] WARNING: Tidak ada berkas .ttl ditemukan di linking_agent/output.")
        print("  [PLANNER] Menggunakan berkas simulasi atau menunggu pipeline dijalankan.")

    # 3. Ambil tugas pertama jika rencana tidak kosong
    current_task = validation_plan.pop(0) if validation_plan else {}

    if current_task:
        print(f"  [PLANNER] Tugas pertama disiapkan: {current_task['file_name']}")
    else:
        print("  [PLANNER] Tidak ada tugas validasi aktif saat ini.")

    return {
        "validation_plan": validation_plan,
        "current_task": current_task,
        "validation_results": [],
        "all_done": False
    }
