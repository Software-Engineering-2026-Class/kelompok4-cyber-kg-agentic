import json
import re
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

from rdflib import Graph, Namespace, URIRef
from rdflib.namespace import RDF

from ..state import LinkingState
from ..config import NAMESPACES, RESOURCE_BASE

NS_CVE = Namespace(NAMESPACES["cve"])
NS_CWE = Namespace(NAMESPACES["cwe"])
NS_CAPEC = Namespace(NAMESPACES["capec"])
NS_CPE = Namespace(NAMESPACES["cpe"])
NS_CVSS = Namespace(NAMESPACES["cvss"])
NS_ATTCK = Namespace(NAMESPACES["attck"])
NS_ICSA = Namespace(NAMESPACES["icsa"])


def executor(state: LinkingState) -> LinkingState:
    task = state.get("current_task")

    if not task:
        print("  [EXECUTOR] Tidak ada tugas yang harus dieksekusi.")
        linked_results = state.get("linked_results", [])
        link_plan = state.get("link_plan", [])
        next_task = link_plan.pop(0) if link_plan else {}
        return {
            "link_plan": link_plan,
            "current_task": next_task,
            "linked_results": linked_results,
        }

    link_type = task["link_type"]
    predicate_str = task["predicate"]
    subject_files = task.get("subject_files", [])

    print(f"  [EXECUTOR] Memproses linking: {link_type} ({predicate_str})...")

    result = {
        "link_type": link_type,
        "predicate": predicate_str,
        "status": "failed",
        "triples_count": 0,
        "output_file": None,
        "error": None,
    }

    try:
        g = Graph()
        for prefix, uri in NAMESPACES.items():
            g.bind(prefix, Namespace(uri))

        predicate_uri = _resolve_predicate(predicate_str)
        triples_count = 0

        if link_type == "cve_to_cwe":
            triples_count = _link_cve_to_cwe(g, subject_files, predicate_uri)
        elif link_type == "cve_to_cpe":
            triples_count = _link_cve_to_cpe(g, subject_files, predicate_uri)
        elif link_type == "cwe_to_capec":
            triples_count = _link_cwe_to_capec(g, subject_files, predicate_uri)
        elif link_type == "capec_to_attck":
            triples_count = _link_capec_to_attck(g, subject_files, predicate_uri)
        elif link_type == "icsa_to_cve":
            triples_count = _link_icsa_to_cve(g, subject_files, predicate_uri)
        else:
            print(f"  [EXECUTOR] WARNING: Tipe linking tidak dikenali: {link_type}")

        out_dir = Path("linking_agent/output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{link_type}.ttl"

        g.serialize(destination=str(out_file), format="turtle")

        result["status"] = "success"
        result["triples_count"] = triples_count
        result["output_file"] = str(out_file)
        print(f"  [EXECUTOR] ✓ Berhasil: {triples_count} triple ditulis ke {out_file}")

    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"  [EXECUTOR] ✗ Error pada {link_type}: {error_msg}")
        result["error"] = str(e)

    linked_results = state.get("linked_results", [])
    linked_results.append(result)

    link_plan = state.get("link_plan", [])
    next_task = link_plan.pop(0) if link_plan else {}

    return {
        "link_plan": link_plan,
        "current_task": next_task,
        "linked_results": linked_results,
    }


def _resolve_predicate(predicate_str: str) -> URIRef:
    if ":" in predicate_str:
        prefix, local = predicate_str.split(":", 1)
        if prefix in NAMESPACES:
            return URIRef(NAMESPACES[prefix] + local)
    return URIRef(predicate_str)


def _load_json_data(file_path: str) -> dict | list:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _sanitize_uri_component(value: str) -> str:
    if not value:
        return value
    value = re.sub(r'<[^>]+>', '', value)
    value = re.sub(r'[\x00-\x1f]', '', value)
    value = re.sub(r'[\s"\'{}<>|\\^`\[\]]', '_', value)
    return value


def _link_cve_to_cwe(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            data = _load_json_data(file_path)
        except Exception as e:
            print(f"  [EXECUTOR] Gagal membaca {file_path}: {e}")
            continue

        vulnerabilities = []
        if isinstance(data, dict) and "vulnerabilities" in data:
            vulnerabilities = data["vulnerabilities"]
        elif isinstance(data, list):
            vulnerabilities = data

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            cve_id = _sanitize_uri_component(cve_id)
            subject_uri = URIRef(RESOURCE_BASE["cve"] + cve_id)
            g.add((subject_uri, RDF.type, NS_CVE.CVE))

            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_value = _sanitize_uri_component(cwe_value)
                        object_uri = URIRef(RESOURCE_BASE["cwe"] + cwe_value)
                        g.add((subject_uri, predicate, object_uri))
                        g.add((object_uri, RDF.type, NS_CWE.CWE))
                        count += 1

    return count


def _link_cve_to_cpe(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            data = _load_json_data(file_path)
        except Exception as e:
            print(f"  [EXECUTOR] Gagal membaca {file_path}: {e}")
            continue

        vulnerabilities = []
        if isinstance(data, dict) and "vulnerabilities" in data:
            vulnerabilities = data["vulnerabilities"]
        elif isinstance(data, list):
            vulnerabilities = data

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            cve_id = _sanitize_uri_component(cve_id)
            subject_uri = URIRef(RESOURCE_BASE["cve"] + cve_id)
            g.add((subject_uri, RDF.type, NS_CVE.CVE))

            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_uri_str = cpe_match.get("criteria", "")
                        if cpe_uri_str:
                            cpe_safe = cpe_uri_str.replace(":", "").replace("/", "")
                            cpe_safe = _sanitize_uri_component(cpe_safe)
                            object_uri = URIRef(RESOURCE_BASE["cpe"] + cpe_safe)
                            g.add((subject_uri, predicate, object_uri))
                            g.add((object_uri, RDF.type, NS_CPE.CPE))
                            count += 1

    return count


def _link_cwe_to_capec(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            if file_path.endswith(".xml"):
                count += _link_cwe_to_capec_xml(g, file_path, predicate)
            elif file_path.endswith(".json"):
                count += _link_cwe_to_capec_json(g, file_path, predicate)
        except Exception as e:
            print(f"  [EXECUTOR] Gagal memproses {file_path}: {e}")
            continue

    return count


def _link_cwe_to_capec_xml(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    tree = ET.parse(file_path)
    root = tree.getroot()

    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag == "Weakness":
            cwe_id = elem.attrib.get("ID")
            if not cwe_id:
                continue

            subject_uri = URIRef(RESOURCE_BASE["cwe"] + f"CWE-{cwe_id}")
            g.add((subject_uri, RDF.type, NS_CWE.CWE))

            for child in elem.iter():
                child_tag = _strip_ns(child.tag)
                if child_tag == "Related_Attack_Pattern":
                    capec_id = child.attrib.get("CAPEC_ID")
                    if capec_id:
                        object_uri = URIRef(RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}")
                        g.add((subject_uri, predicate, object_uri))
                        g.add((object_uri, RDF.type, NS_CAPEC.CAPEC))
                        count += 1

    return count


def _link_cwe_to_capec_json(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    data = _load_json_data(file_path)

    weaknesses = []
    if isinstance(data, dict):
        weaknesses = data.get("Weaknesses", data.get("weaknesses", []))
    elif isinstance(data, list):
        weaknesses = data

    for weakness in weaknesses:
        cwe_id = weakness.get("ID") or weakness.get("id")
        if not cwe_id:
            attribs = weakness.get("attribs", {})
            cwe_id = attribs.get("ID")
        if not cwe_id:
            continue

        subject_uri = URIRef(RESOURCE_BASE["cwe"] + f"CWE-{cwe_id}")
        g.add((subject_uri, RDF.type, NS_CWE.CWE))

        related_patterns = weakness.get("Related_Attack_Patterns", [])
        if isinstance(related_patterns, dict):
            related_patterns = related_patterns.get("Related_Attack_Pattern", [])
        if isinstance(related_patterns, dict):
            related_patterns = [related_patterns]

        for pattern in related_patterns:
            capec_id = pattern.get("CAPEC_ID") or pattern.get("capec_id")
            if capec_id:
                object_uri = URIRef(RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}")
                g.add((subject_uri, predicate, object_uri))
                g.add((object_uri, RDF.type, NS_CAPEC.CAPEC))
                count += 1

    return count


def _link_capec_to_attck(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            if file_path.endswith(".xml"):
                count += _link_capec_to_attck_xml(g, file_path, predicate)
            elif file_path.endswith(".json"):
                count += _link_capec_to_attck_json(g, file_path, predicate)
        except Exception as e:
            print(f"  [EXECUTOR] Gagal memproses {file_path}: {e}")
            continue

    return count


def _link_capec_to_attck_xml(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    tree = ET.parse(file_path)
    root = tree.getroot()

    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag == "Attack_Pattern":
            capec_id = elem.attrib.get("ID")
            if not capec_id:
                continue

            subject_uri = URIRef(RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}")
            g.add((subject_uri, RDF.type, NS_CAPEC.CAPEC))

            for child in elem.iter():
                child_tag = _strip_ns(child.tag)
                if child_tag == "Taxonomy_Mapping":
                    taxonomy_name = child.attrib.get("Taxonomy_Name", "")
                    if "ATTACK" in taxonomy_name.upper():
                        for entry in child.iter():
                            entry_tag = _strip_ns(entry.tag)
                            if entry_tag == "Entry_ID" and entry.text:
                                technique_id = entry.text.strip()
                                # Tambah prefix T kalau belum ada
                                if not technique_id.startswith("T"):
                                    technique_id = "T" + technique_id
                                object_uri = URIRef(RESOURCE_BASE["attck"] + technique_id)
                                g.add((subject_uri, predicate, object_uri))
                                g.add((object_uri, RDF.type, NS_ATTCK.AttackPattern))
                                count += 1

    return count


def _link_capec_to_attck_json(g: Graph, file_path: str, predicate: URIRef) -> int:
    count = 0
    data = _load_json_data(file_path)

    patterns = []
    if isinstance(data, dict):
        patterns = data.get("Attack_Patterns", data.get("attack_patterns", []))
    elif isinstance(data, list):
        patterns = data

    for pattern in patterns:
        capec_id = pattern.get("ID") or pattern.get("id")
        if not capec_id:
            attribs = pattern.get("attribs", {})
            capec_id = attribs.get("ID")
        if not capec_id:
            continue

        subject_uri = URIRef(RESOURCE_BASE["capec"] + f"CAPEC-{capec_id}")
        g.add((subject_uri, RDF.type, NS_CAPEC.CAPEC))

        taxonomy_mappings = pattern.get("Taxonomy_Mappings", [])
        if isinstance(taxonomy_mappings, dict):
            taxonomy_mappings = taxonomy_mappings.get("Taxonomy_Mapping", [])
        if isinstance(taxonomy_mappings, dict):
            taxonomy_mappings = [taxonomy_mappings]

        for mapping in taxonomy_mappings:
            taxonomy_name = mapping.get("Taxonomy_Name", "")
            if "ATTACK" in taxonomy_name.upper():
                entry_id = mapping.get("Entry_ID", "")
                if entry_id:
                    if not entry_id.startswith("T"):
                        entry_id = "T" + entry_id
                    object_uri = URIRef(RESOURCE_BASE["attck"] + entry_id)
                    g.add((subject_uri, predicate, object_uri))
                    g.add((object_uri, RDF.type, NS_ATTCK.AttackPattern))
                    count += 1

    return count


def _link_icsa_to_cve(g: Graph, subject_files: list[str], predicate: URIRef) -> int:
    count = 0
    for file_path in subject_files:
        try:
            data = _load_json_data(file_path)
        except Exception as e:
            print(f"  [EXECUTOR] Gagal membaca {file_path}: {e}")
            continue

        vulnerabilities = []
        if isinstance(data, dict):
            vulnerabilities = data.get("vulnerabilities", [])
        elif isinstance(data, list):
            vulnerabilities = data

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            cve_id = _sanitize_uri_component(cve_id)
            vendor = _sanitize_uri_component(vuln.get("vendorProject", "unknown"))
            product = _sanitize_uri_component(vuln.get("product", "unknown"))
            icsa_id = f"{vendor}_{product}_{cve_id}".replace(" ", "_")

            subject_uri = URIRef(RESOURCE_BASE["icsa"] + icsa_id)
            g.add((subject_uri, RDF.type, NS_ICSA.ICSA))

            object_uri = URIRef(RESOURCE_BASE["cve"] + cve_id)
            g.add((subject_uri, predicate, object_uri))
            g.add((object_uri, RDF.type, NS_CVE.CVE))
            count += 1

    return count
