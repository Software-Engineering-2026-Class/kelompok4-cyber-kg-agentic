import sys
from pathlib import Path

# Daftarkan root path agar paket validation_agent bisa di-import
current_file_path = Path(__file__).resolve()
parent_dir = current_file_path.parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from validation_agent.nodes.executor import executor

# =====================================================================
# DATA SIMULASI (SYNTHESIZED RDF TURTLE DATA)
# =====================================================================

VALID_TURTLE = """@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .
@prefix cwe: <http://w3id.org/sepses/vocab/ref/cwe#> .
@prefix cpe: <http://w3id.org/sepses/vocab/ref/cpe#> .
@prefix capec: <http://w3id.org/sepses/vocab/ref/capec#> .
@prefix attck: <http://w3id.org/sepses/vocab/ref/attack#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<http://w3id.org/sepses/resource/cve/CVE-2026-1234> a cve:CVE ;
    cve:id "CVE-2026-1234"^^xsd:string ;
    cve:description "A mock valid CVE vulnerability description."^^xsd:string ;
    cve:hasCWE <http://w3id.org/sepses/resource/cwe/CWE-79> ;
    cve:hasCPE <http://w3id.org/sepses/resource/cpe/CPE-1> .

<http://w3id.org/sepses/resource/cpe/CPE-1> a cpe:CPE ;
    cpe:id "CPE-1"^^xsd:string ;
    cpe:cpe23Uri "cpe:2.3:a:mock:software:1.0:*:*:*:*:*:*:*"^^xsd:string .

<http://w3id.org/sepses/resource/cwe/CWE-79> a cwe:CWE ;
    cwe:id "CWE-79"^^xsd:string ;
    cwe:name "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"^^xsd:string ;
    cwe:description "Cross-site scripting (XSS) vulnerability."^^xsd:string ;
    cwe:hasCAPEC <http://w3id.org/sepses/resource/capec/CAPEC-85> .

<http://w3id.org/sepses/resource/capec/CAPEC-85> a capec:CAPEC ;
    capec:id "CAPEC-85"^^xsd:string ;
    capec:name "AJAX Injection"^^xsd:string ;
    capec:description "An attacker injects malicious AJAX code."^^xsd:string ;
    capec:hasRelatedAttackPattern <http://w3id.org/sepses/resource/attack/T1059> .

<http://w3id.org/sepses/resource/attack/T1059> a attck:AttackPattern ;
    attck:id "T1059"^^xsd:string ;
    attck:name "Command and Scripting Interpreter"^^xsd:string ;
    attck:techniqueId "T1059"^^xsd:string .
"""

INVALID_TURTLE = """@prefix cve: <http://w3id.org/sepses/vocab/ref/cve#> .
@prefix cwe: <http://w3id.org/sepses/vocab/ref/cwe#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

# 1. Invalid ID Format (CVE-123 instead of CVE-YYYY-NNNN) dan Ketiadaan description
<http://w3id.org/sepses/resource/cve/CVE-123> a cve:CVE ;
    cve:id "CVE-123"^^xsd:string .

# 2. Ketiadaan name dan id wajib untuk CWE
<http://w3id.org/sepses/resource/cwe/CWE-bad> a cwe:CWE ;
    cwe:description "Malformed CWE weakness without ID and Name."^^xsd:string .

# 3. Broken link (Relasi menunjuk ke URI ilegal/bukan CWE)
<http://w3id.org/sepses/resource/cve/CVE-2026-9999> a cve:CVE ;
    cve:id "CVE-2026-9999"^^xsd:string ;
    cve:description "This CVE links to a broken resource."^^xsd:string ;
    cve:hasCWE <http://w3id.org/invalid-prefix/broken-resource> .
"""


def run_tests():
    """
    Menjalankan pengujian otomatis untuk memverifikasi akurasi pendeteksian anomali.
    """
    print("=" * 60)
    print("  AUTOMATED VERIFICATION — SEPSES Validation Agent")
    print("=" * 60)

    # 1. Persiapkan folder scratch dan tulis berkas simulasi
    scratch_dir = Path("validation_agent/scratch")
    scratch_dir.mkdir(parents=True, exist_ok=True)

    valid_file = scratch_dir / "valid_simulated.ttl"
    invalid_file = scratch_dir / "invalid_simulated.ttl"

    with open(valid_file, "w", encoding="utf-8") as f:
        f.write(VALID_TURTLE)
    with open(invalid_file, "w", encoding="utf-8") as f:
        f.write(INVALID_TURTLE)

    print("\n[TEST] 1. Menjalankan validasi berkas Turtle yang VALID...")
    state_valid = {
        "current_task": {
            "file_name": "valid_simulated.ttl",
            "file_path": str(valid_file),
            "link_type": "cve_to_cwe",
            "description": "Pengujian Berkas Valid Simulasi"
        },
        "validation_plan": [],
        "validation_results": [],
    }

    res_valid = executor(state_valid)
    result_valid = res_valid["validation_results"][0]

    # Asersi Berkas Valid
    assert result_valid["status"] == "success", "Seharusnya berhasil membaca berkas valid."
    assert result_valid["errors_count"] == 0, "Berkas valid tidak boleh memiliki ERROR."
    assert result_valid["warnings_count"] == 0, "Berkas valid simulasi tidak boleh memiliki WARNING."
    print("  >> ✓ PASSED: Berkas valid terbaca dengan 0 Error dan 0 Warning.")

    print("\n[TEST] 2. Menjalankan validasi berkas Turtle yang INVALID...")
    state_invalid = {
        "current_task": {
            "file_name": "invalid_simulated.ttl",
            "file_path": str(invalid_file),
            "link_type": "cve_to_cwe",
            "description": "Pengujian Berkas Invalid Simulasi"
        },
        "validation_plan": [],
        "validation_results": [],
    }

    res_invalid = executor(state_invalid)
    result_invalid = res_invalid["validation_results"][0]

    # Asersi Berkas Invalid
    assert result_invalid["status"] == "success", "Seharusnya berhasil memparse berkas meski isinya melanggar aturan."
    
    # Cetak temuan di berkas invalid
    print(f"  >> Terdeteksi {result_invalid['errors_count']} Error dan {result_invalid['warnings_count']} Warning.")
    for f in result_invalid["findings"]:
        print(f"     * [{f['level']}] Property '{f['property'].split('#')[-1]}': {f['message']}")

    # Verifikasi temuan anomali
    assert result_invalid["errors_count"] >= 3, "Harus mendeteksi minimal 3 kesalahan (Format CVE ID, Ketiadaan CWE ID, Ketiadaan CWE Name)."
    assert result_invalid["warnings_count"] >= 2, "Harus mendeteksi ketiadaan deskripsi CVE-123 dan broken link hasCWE."
    
    print("\n" + "=" * 60)
    print("  VERIFIKASI SUKSES: 100% ANOMALI BERHASIL DIDETEKSI!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_tests()
