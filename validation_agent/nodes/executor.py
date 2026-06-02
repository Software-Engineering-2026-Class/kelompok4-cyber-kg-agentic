import re
import traceback
from pathlib import Path
from rdflib import Graph, URIRef, RDF
from ..state import ValidationState
from ..config import VALIDATION_RULES, NAMESPACES


def executor(state: ValidationState) -> ValidationState:
    """
    Node Executor: Membaca berkas Turtle aktif, memvalidasi sintaks,
    kelas ontologi, ketiadaan triple wajib, dan mendeteksi anomali.
    """
    task = state.get("current_task")

    if not task:
        print("  [EXECUTOR] Tidak ada tugas validasi aktif.")
        validation_results = state.get("validation_results", [])
        validation_plan = state.get("validation_plan", [])
        next_task = validation_plan.pop(0) if validation_plan else {}
        return {
            "validation_plan": validation_plan,
            "current_task": next_task,
            "validation_results": validation_results,
        }

    file_name = task["file_name"]
    file_path = task["file_path"]
    link_type = task["link_type"]

    print(f"\n  [EXECUTOR] Memproses validasi berkas: {file_name} ({task['description']})...")

    # Inisialisasi struktur hasil evaluasi berkas
    result = {
        "file_name": file_name,
        "file_path": file_path,
        "link_type": link_type,
        "status": "failed",
        "total_triples": 0,
        "validated_subjects": 0,
        "critical_errors_count": 0,
        "errors_count": 0,
        "warnings_count": 0,
        "findings": [],
        "error_detail": None
    }

    try:
        # 1. Parsing Berkas Turtle (.ttl) menggunakan RDFLib
        g = Graph()
        for prefix, uri in NAMESPACES.items():
            g.bind(prefix, URIRef(uri))

        # Load base data dari parser_agent/output sebagai konteks tambahan
        parser_output_dir = Path("parser_agent/output")
        BASE_TTL_FILES = [
            "attck_enterprise.ttl",
            "attck_ics.ttl",
            "capec.ttl",
            "cwe.ttl",
            "cve.ttl",
            "cpe.ttl",
            "icsa.ttl",
        ]
        for base_file in BASE_TTL_FILES:
            base_path = parser_output_dir / base_file
            if base_path.exists():
                g.parse(str(base_path), format="turtle")

        # Baru load file linking yang sedang divalidasi
        g.parse(file_path, format="turtle")
        total_triples = len(g)
        result["total_triples"] = total_triples
        print(f"  [EXECUTOR] ✓ Berhasil mengurai {total_triples:,} triple dari {file_name}.")

        # 2. Cari seluruh subjek unik dalam graf
        subjects = set(g.subjects())
        result["validated_subjects"] = len(subjects)

        # 3. Iterasi pemeriksaan untuk setiap subjek
        for subj in sorted(subjects):
            if not isinstance(subj, URIRef):
                continue

            # Dapatkan kelas subjek (rdf:type)
            types = list(g.objects(subj, RDF.type))
            if not types:
                # Subjek tidak memiliki deklarasi tipe kelas
                result["findings"].append({
                    "subject": str(subj),
                    "property": "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
                    "level": "WARNING",
                    "message": "Entitas tidak memiliki deklarasi kelas formal (rdf:type).",
                    "rule": "Ontology Conformance Check"
                })
                result["warnings_count"] += 1
                continue

            for subj_type in types:
                type_str = str(subj_type)
                
                # Jika kelas subjek terdaftar dalam matriks aturan validasi kita
                if type_str in VALIDATION_RULES:
                    rules = VALIDATION_RULES[type_str]

                    # A. VALIDASI PROPERTI WAJIB (MANDATORY PROPERTIES)
                    if "mandatory_properties" in rules:
                        for prop_uri, prop_rule in rules["mandatory_properties"].items():
                            pred_ref = URIRef(prop_uri)
                            values = list(g.objects(subj, pred_ref))

                            if not values:
                                severity = prop_rule.get("severity", "WARNING")
                                result["findings"].append({
                                    "subject": str(subj),
                                    "property": prop_uri,
                                    "level": severity,
                                    "message": f"Ketiadaan properti wajib: {prop_rule.get('description', '')}",
                                    "rule": "Missing Mandatory Triple Detection"
                                })
                                if severity == "ERROR":
                                    result["errors_count"] += 1
                                else:
                                    result["warnings_count"] += 1
                            else:
                                # Periksa kepatuhan format regex jika ada
                                if "regex" in prop_rule:
                                    pattern = prop_rule["regex"]
                                    for val in values:
                                        val_str = str(val)
                                        if not re.match(pattern, val_str):
                                            result["findings"].append({
                                                "subject": str(subj),
                                                "property": prop_uri,
                                                "level": "ERROR",
                                                "message": f"Anomali format literal '{val_str}' tidak sesuai regex standar '{pattern}'. {prop_rule.get('description', '')}",
                                                "rule": "Format Regex & Value Check"
                                            })
                                            result["errors_count"] += 1

                    # B. VALIDASI RELASI DAN KONTROL LINK (LINKS VALIDATION)
                    if "links" in rules:
                        for prop_uri, link_rule in rules["links"].items():
                            pred_ref = URIRef(prop_uri)
                            links = list(g.objects(subj, pred_ref))

                            if not links:
                                severity = link_rule.get("severity", "WARNING")
                                result["findings"].append({
                                    "subject": str(subj),
                                    "property": prop_uri,
                                    "level": severity,
                                    "message": f"Ketiadaan relasi wajib ke kelas {link_rule['target_class'].split('#')[-1]}: {link_rule.get('description', '')}",
                                    "rule": "Missing Relationship Link"
                                })
                                if severity == "ERROR":
                                    result["errors_count"] += 1
                                else:
                                    result["warnings_count"] += 1
                            else:
                                # Periksa validitas referensi tujuan relasi (Broken Links Heuristic)
                                target_class_uri = link_rule["target_class"]
                                for target in links:
                                    target_str = str(target)
                                    
                                    # Pengecekan 1: Apakah bertipe target_class dalam grafik saat ini?
                                    target_types = list(g.objects(target, RDF.type))
                                    has_proper_type = URIRef(target_class_uri) in target_types

                                    # Pengecekan 2: Heuristik URI Base (mencegah warning palsu jika data dideklarasikan di file lain)
                                    class_indicator = target_class_uri.split("#")[-1].lower()
                                    has_proper_uri_prefix = f"/{class_indicator}/" in target_str or f"#{class_indicator}" in target_str
                                    
                                    if not has_proper_type and not has_proper_uri_prefix:
                                        result["findings"].append({
                                            "subject": str(subj),
                                            "property": prop_uri,
                                            "level": link_rule.get("severity", "WARNING"),
                                            "message": f"Broken Link / Anomali Referensi: Objek '{target_str}' tidak bertipe {class_indicator.upper()} atau format URI tidak sesuai.",
                                            "rule": "Broken Link & Target Type Check"
                                        })
                                        if link_rule.get("severity") == "ERROR":
                                            result["errors_count"] += 1
                                        else:
                                            result["warnings_count"] += 1

        result["status"] = "success"
        print(f"  [EXECUTOR] ✓ Validasi selesai. Temuan: {result['errors_count']} Error, {result['warnings_count']} Warning.")

    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"  [EXECUTOR] ✗ Kegagalan kritis saat membaca {file_name}: {e}")
        result["status"] = "failed"
        result["critical_errors_count"] = 1
        result["error_detail"] = error_msg
        result["findings"].append({
            "subject": file_path,
            "property": "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
            "level": "CRITICAL",
            "message": f"Syntax Error / Gagal parse file Turtle: {str(e)}",
            "rule": "RDF Syntax Parser Check"
        })

    # Simpan hasil tugas aktif ke state
    validation_results = state.get("validation_results", [])
    validation_results.append(result)

    # Dapatkan tugas berikutnya dari antrean rencana validasi
    validation_plan = state.get("validation_plan", [])
    next_task = validation_plan.pop(0) if validation_plan else {}

    return {
        "validation_plan": validation_plan,
        "current_task": next_task,
        "validation_results": validation_results,
    }
