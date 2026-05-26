import json
from datetime import datetime
from pathlib import Path
from ..state import ValidationState


def reviewer(state: ValidationState) -> ValidationState:
    """
    Node Reviewer: Mengevaluasi seluruh temuan, menghitung skor kepatuhan semantik,
    dan menulis berkas laporan fisik (Markdown premium & JSON terstruktur).
    """
    print("\n  [REVIEWER] Mengevaluasi seluruh temuan dan menyusun laporan akhir...")

    results = state.get("validation_results", [])
    messages = state.get("messages", [])

    if not results:
        print("  [REVIEWER] WARNING: Tidak ada hasil validasi untuk dievaluasi.")
        return {
            "all_done": True,
            "messages": messages + [{"role": "assistant", "content": "Validasi selesai tanpa ada berkas yang dievaluasi."}]
        }

    # 1. Agregasi Statistik Global
    total_files = len(results)
    successful_parses = sum(1 for r in results if r["status"] == "success")
    failed_parses = sum(1 for r in results if r["status"] == "failed")
    
    total_triples = sum(r["total_triples"] for r in results)
    total_subjects = sum(r["validated_subjects"] for r in results)
    
    total_critical = sum(r["critical_errors_count"] for r in results)
    total_errors = sum(r["errors_count"] for r in results)
    total_warnings = sum(r["warnings_count"] for r in results)

    # Menghitung Skor Kualitas Semantik (Semantic Quality Index)
    # Formula: Kepatuhan = (1 - (Total Error / Max(1, Total Triples))) * 100
    quality_score = 100.0
    if total_triples > 0:
        quality_score = max(0.0, (1.0 - (total_errors + total_critical * 10) / total_triples) * 100)
    
    quality_score_str = f"{quality_score:.2f}%"

    # Predikat Penjaminan Mutu
    quality_tier = "EXCELLENT (A)"
    if quality_score < 95.0:
        quality_tier = "GOOD (B)"
    if quality_score < 85.0:
        quality_tier = "FAIR (C)"
    if quality_score < 70.0:
        quality_tier = "POOR (D / FAILED)"

    # 2. Persiapkan Berkas & Output Directory
    reports_dir = Path("validation_agent/output/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamp_readable = datetime.now().strftime("%d %B %Y, %H:%M:%S WIB")

    md_report_file = reports_dir / f"validation_report_{timestamp_filename}.md"
    json_report_file = reports_dir / f"validation_report_{timestamp_filename}.json"

    # 3. Bangun Premium Markdown Report Content (Bilingual/Academic Indonesian)
    md_content = f"""# LAPORAN PENJAMINAN MUTU SEMANTIK (SEMANTIC QUALITY ASSURANCE REPORT)
**EVALUASI CONFORMANCE, MANDATORY TRIPLES, DAN ANOMALI PADA SEPSES CYBERSECURITY KNOWLEDGE GRAPH**

---

## COVER PAGE
* **Nama Sistem:** SEPSES Cyber-KG Validation Agent (Validation Agent)
* **Waktu Validasi:** {timestamp_readable}
* **Jumlah Berkas Dievaluasi:** {total_files} berkas Turtle (`.ttl`)
* **Total Triple Dievaluasi:** {total_triples:,} Triples
* **Status Parsing Sintaks:** {successful_parses} Berhasil, {failed_parses} Gagal
* **Versi Laporan:** 1.0.0 (Formal Release)
* **Sponsor / Klien:** Laboratorium Rekayasa Perangkat Lunak & Sistem Informasi

---

## 1. Ringkasan Eksekutif (Executive Summary)
Laporan ini disusun secara otomatis oleh **Validation Agent** otonom untuk mengevaluasi kualitas data semantik grafik hubungan keamanan siber hasil konversi pipeline SEPSES. Evaluasi mencakup pemeriksaan kepatuhan ontologi (*ontology conformance*), keberadaan *triple* wajib (*missing mandatory triples*), dan deteksi anomali literal serta referensi hubungan (*broken links*).

Berdasarkan hasil evaluasi menyeluruh, grafik instansi yang diuji mendapatkan predikat:
> ### **SEMANTIC COMPLIANCE INDEX: {quality_score_str}**
> **MUTU KUALITAS: {quality_tier}**
> 
> *Catatan: Skor kualitas dihitung berdasarkan rasio kesalahan kritis dan anomali sintaksis terhadap total triple semantik yang dihasilkan.*

---

## 2. Metrik Evaluasi Global (Global Evaluation Metrics)
Berikut adalah ringkasan performa penjaminan mutu semantik per berkas grafik:

| Nama Berkas | Total Triple | Subjek Unik | Error | Warning | Status Parse |
| :--- | :---: | :---: | :---: | :---: | :---: |
"""
    for r in results:
        status_icon = "✓ SUCCESS" if r["status"] == "success" else "✗ FAILED"
        md_content += f"| `{r['file_name']}` | {r['total_triples']:,} | {r['validated_subjects']:,} | {r['errors_count'] + r['critical_errors_count']} | {r['warnings_count']} | {status_icon} |\n"

    md_content += f"""
---

## 3. Rincian Temuan Anomali Semantik (Detailed Findings)
Berikut adalah daftar lengkap pelanggaran, ketiadaan data wajib, dan anomali semantik yang berhasil dideteksi dalam grafik:

"""

    findings_count = 0
    for r in results:
        md_content += f"### 3.{findings_count + 1} Berkas: `{r['file_name']}`\n"
        if not r["findings"]:
            md_content += "_✓ Tidak ditemukan anomali atau pelanggaran semantik pada berkas ini._\n\n"
        else:
            md_content += "| Subjek RDF (Subject) | Properti / Predikat | Level | Deskripsi Pelanggaran | Aturan (Rule) |\n"
            md_content += "| :--- | :--- | :---: | :--- | :--- |\n"
            for f in r["findings"]:
                # Potong URI panjang agar tabel markdown rapi
                subj_short = f["subject"].split("/")[-1] if "/" in f["subject"] else f["subject"]
                prop_short = f["property"].split("#")[-1] if "#" in f["property"] else (f["property"].split("/")[-1] if "/" in f["property"] else f["property"])
                
                md_content += f"| `...{subj_short}` | `{prop_short}` | **{f['level']}** | {f['message']} | {f['rule']} |\n"
            md_content += "\n"
        findings_count += 1

    md_content += f"""
---

## 4. Analisis & Rekomendasi Mitigasi (Architectural Recommendations)

Berdasarkan pola temuan dalam penjaminan mutu, berikut adalah tindakan perbaikan yang direkomendasikan untuk penyempurnaan pipeline:

1. **Kasus Missing Mandatory Properties (misal deskripsi CVE/CWE kosong):**
   * *Analisis:* Hal ini menandakan data mentah dari API NVD atau berkas XML MITRE tidak menyertakan deskripsi bahasa Inggris (`en`) yang diekstrak oleh parser, atau data tersebut memang kosong dari sumber aslinya.
   * *Mitigasi:* Tambahkan penanganan fallback di `parser_agent` untuk mengisi deskripsi standar default (misal: "No description provided from NVD source") alih-alih membiarkan properti tersebut absen.

2. **Kasus Broken Links / Referensi Tipe Rusak (dangling pointers):**
   * *Analisis:* Terjadi karena file hubungan (seperti `cve_to_cwe.ttl`) menunjuk ke URI CWE eksternal tanpa adanya deklarasi kelas formal `sepses:CWE` di dalam file relasi tersebut.
   * *Mitigasi:* Ini adalah perilaku wajar jika grafik dimuat secara modular. Namun untuk visualisasi graf utuh, pastikan seluruh grafik hasil konversi (`cve_to_cwe.ttl`, `cwe_to_capec.ttl`, dll.) dimuat secara bersamaan (*merged graph*) ke dalam SPARQL Triplestore untuk menyelesaikan referensi silang secara utuh.

3. **Kasus Anomali Format Regex (ID Malformed):**
   * *Analisis:* Disebabkan oleh karakter penyehat (*sanitization*) yang berlebih saat konversi URI atau ketidakcocokan ekstraksi ID dari data mentah.
   * *Mitigasi:* Tinjau ulang metode `_sanitize_uri_component` di `linking_agent/nodes/executor.py` untuk memastikan string ID bersih tanpa modifikasi karakter ilegal.

---
*Dokumen ini sah dirilis secara otomatis oleh Validation Agent, Laboratorium Rekayasa Perangkat Lunak.*
"""

    # Write MD Report
    with open(md_report_file, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"  [REVIEWER] ✓ Laporan Markdown premium ditulis ke: {md_report_file}")

    # 4. Bangun JSON Report Content
    json_data = {
        "timestamp": timestamp_readable,
        "compliance_score": quality_score,
        "quality_tier": quality_tier,
        "statistics": {
            "total_files": total_files,
            "successful_parses": successful_parses,
            "failed_parses": failed_parses,
            "total_triples": total_triples,
            "total_subjects": total_subjects,
            "critical_errors": total_critical,
            "errors": total_errors,
            "warnings": total_warnings
        },
        "results": results
    }

    # Write JSON Report
    with open(json_report_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    print(f"  [REVIEWER] ✓ Laporan JSON terstruktur ditulis ke: {json_report_file}")

    # 5. Susun Pesan Ringkasan Akhir
    summary_message = (
        f"Validasi penjaminan mutu semantik selesai untuk {total_files} berkas Turtle. "
        f"Skor Kepatuhan Semantik Graf: **{quality_score_str}** ({quality_tier}). "
        f"Ditemukan {total_errors} Error dan {total_warnings} Warning. "
        f"Laporan fisik lengkap telah ditulis ke berkas Markdown: `{md_report_file}` "
        f"dan JSON: `{json_report_file}`."
    )
    print(f"  [REVIEWER] Summary: {summary_message}")

    return {
        "all_done": True,
        "messages": messages + [{"role": "assistant", "content": summary_message}]
    }
