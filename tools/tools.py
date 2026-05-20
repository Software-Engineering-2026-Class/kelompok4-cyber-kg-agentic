"""
tools.py  —  All tools the AI agent can call.

Each tool is a plain Python function decorated with @tool_schema so the
agent dispatcher knows its JSON schema.  The agent calls them by name.
"""

import io, json, re, zipfile, logging, hashlib, os, time
from typing import Any
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

import requests
from rdflib import Graph, ConjunctiveGraph, URIRef, Literal, BNode, Namespace
from rdflib.namespace import RDF, RDFS, OWL, XSD, DCTERMS

# local
from ontology.namespaces import (
    CVEVocab, CVSSVocab, CWEVocab, CAPECVocab, CPEVocab, ATTVocab,
    CVE_NS, CWE_NS, CVSS, CAPEC, CPE_NS, ATT,
    R_CVE, R_CWE, R_CPE, R_CAPEC, R_ATT,
    GRAPH_CVE, GRAPH_CWE, GRAPH_CPE, GRAPH_CAPEC, GRAPH_ATT,
    cve_uri, cwe_uri, capec_uri, cpe_uri,
)

log = logging.getLogger("tools")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# ── Tool registry ─────────────────────────────────────────────────────────────
TOOL_REGISTRY: dict[str, dict] = {}

def tool(description: str, params: dict):
    """Decorator that registers a function as a callable agent tool."""
    def decorator(fn):
        TOOL_REGISTRY[fn.__name__] = {
            "description": description,
            "parameters": params,
            "fn": fn,
        }
        @wraps(fn)
        def wrapper(*a, **kw):
            return fn(*a, **kw)
        return wrapper
    return decorator

def get_tool_schemas() -> list[dict]:
    """Return OpenAI-style tool schemas for every registered tool."""
    schemas = []
    for name, meta in TOOL_REGISTRY.items():
        schemas.append({
            "name": name,
            "description": meta["description"],
            "input_schema": {
                "type": "object",
                "properties": meta["parameters"],
                "required": list(meta["parameters"].keys()),
            },
        })
    return schemas

def call_tool(name: str, args: dict) -> Any:
    if name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {name}")
    return TOOL_REGISTRY[name]["fn"](**args)


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 1 — fetch_source
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Download a cybersecurity data source from a URL and return its raw "
        "text content (auto-decompresses .zip). "
        "Returns {'content': str, 'format': 'json'|'xml'|'csv', 'size': int, 'etag': str}."
    ),
    params={
        "url": {"type": "string", "description": "URL to download"},
        "cache": {"type": "boolean", "description": "Cache to disk to avoid re-downloading"},
    },
)
def fetch_source(url: str, cache: bool = True) -> dict:
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_path = OUTPUT_DIR / f"cache_{cache_key}"

    if cache and cache_path.exists():
        log.info(f"[fetch_source] cache hit: {url}")
        raw = cache_path.read_bytes()
    else:
        log.info(f"[fetch_source] downloading: {url}")
        r = requests.get(url, timeout=120, headers={"User-Agent": "cyber-kg-agent/1.0"})
        r.raise_for_status()
        raw = r.content
        if cache:
            cache_path.write_bytes(raw)

    # decompress zip
    if url.endswith(".zip") or raw[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                names = zf.namelist()
                # pick first xml/json/csv file
                target = next(
                    (n for n in names if n.endswith(('.xml', '.json', '.csv'))),
                    names[0]
                )
                raw = zf.read(target)
                log.info(f"[fetch_source] extracted {target} from zip")
        except Exception as e:
            log.warning(f"[fetch_source] zip extraction failed: {e}")

    text = raw.decode("utf-8", errors="replace")

    # detect format
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        fmt = "json"
    elif stripped.startswith("<"):
        fmt = "xml"
    else:
        fmt = "csv"

    return {"content": text, "format": fmt, "size": len(text), "etag": cache_key}


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 2 — parse_cve
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Parse NVD CVE JSON content into structured records. "
        "Returns list of CVE dicts with id, description, cvss2, cvss3, cpes, cwes, dates."
    ),
    params={
        "json_content": {"type": "string", "description": "Raw NVD JSON string"},
        "max_items":    {"type": "integer", "description": "Max CVEs to parse (0 = all)"},
    },
)
def parse_cve(json_content: str, max_items: int = 0) -> list[dict]:
    data = json.loads(json_content)
    items = data.get("CVE_Items", data.get("vulnerabilities", []))
    out = []
    for i, item in enumerate(items):
        if max_items and i >= max_items:
            break
        try:
            # NVD 1.1 format
            if "cve" in item and "CVE_data_meta" in item.get("cve", {}):
                rec = _parse_nvd11(item)
            # NVD 2.0 format
            elif "cve" in item and "id" in item.get("cve", {}):
                rec = _parse_nvd20(item["cve"])
            else:
                continue
            out.append(rec)
        except Exception as e:
            log.debug(f"CVE parse error item {i}: {e}")
    log.info(f"[parse_cve] parsed {len(out)} CVEs")
    return out


def _parse_nvd11(item: dict) -> dict:
    cve_node = item["cve"]
    cve_id   = cve_node["CVE_data_meta"]["ID"]
    descs    = cve_node.get("description", {}).get("description_data", [])
    desc     = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    # CPEs
    cpes = []
    for node in item.get("configurations", {}).get("nodes", []):
        for m in node.get("cpe_match", []) + [c for child in node.get("children", []) for c in child.get("cpe_match", [])]:
            if m.get("vulnerable"):
                cpes.append(m["cpe23Uri"])

    # CWEs
    cwes = []
    for prob in cve_node.get("problemtype", {}).get("problemtype_data", []):
        for d in prob.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # CVSS
    impact = item.get("impact", {})
    cvss2, cvss3 = None, None
    if "baseMetricV2" in impact:
        m2 = impact["baseMetricV2"]["cvssV2"]
        cvss2 = {
            "version": "2.0",
            "baseScore": impact["baseMetricV2"].get("cvssV2", {}).get("baseScore"),
            "vectorString": m2.get("vectorString"),
            "accessVector": m2.get("accessVector"),
            "confidentialityImpact": m2.get("confidentialityImpact"),
            "integrityImpact": m2.get("integrityImpact"),
            "availabilityImpact": m2.get("availabilityImpact"),
        }
    if "baseMetricV3" in impact:
        m3 = impact["baseMetricV3"]["cvssV3"]
        cvss3 = {
            "version": m3.get("version", "3.1"),
            "baseScore": m3.get("baseScore"),
            "vectorString": m3.get("vectorString"),
            "attackVector": m3.get("attackVector"),
            "attackComplexity": m3.get("attackComplexity"),
            "confidentialityImpact": m3.get("confidentialityImpact"),
            "integrityImpact": m3.get("integrityImpact"),
            "availabilityImpact": m3.get("availabilityImpact"),
        }

    pub  = item.get("publishedDate", "")
    mod  = item.get("lastModifiedDate", "")
    return {"id": cve_id, "description": desc, "cpes": cpes, "cwes": cwes,
            "cvss2": cvss2, "cvss3": cvss3, "published": pub, "modified": mod}


def _parse_nvd20(cve: dict) -> dict:
    cve_id = cve["id"]
    descs  = cve.get("descriptions", [])
    desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    cpes = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpes.append(m.get("criteria", ""))

    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    cvss2, cvss3 = None, None
    for metric in cve.get("metrics", {}).get("cvssMetricV2", []):
        d = metric.get("cvssData", {})
        cvss2 = {"version": "2.0",
                 "baseScore": d.get("baseScore"), "vectorString": d.get("vectorString"),
                 "accessVector": d.get("accessVector"),
                 "confidentialityImpact": d.get("confidentialityImpact"),
                 "integrityImpact": d.get("integrityImpact"),
                 "availabilityImpact": d.get("availabilityImpact")}
        break
    for metric in cve.get("metrics", {}).get("cvssMetricV31", []) + cve.get("metrics", {}).get("cvssMetricV30", []):
        d = metric.get("cvssData", {})
        cvss3 = {"version": d.get("version", "3.1"),
                 "baseScore": d.get("baseScore"), "vectorString": d.get("vectorString"),
                 "attackVector": d.get("attackVector"),
                 "attackComplexity": d.get("attackComplexity"),
                 "confidentialityImpact": d.get("confidentialityImpact"),
                 "integrityImpact": d.get("integrityImpact"),
                 "availabilityImpact": d.get("availabilityImpact")}
        break

    return {"id": cve_id, "description": desc, "cpes": cpes, "cwes": cwes,
            "cvss2": cvss2, "cvss3": cvss3,
            "published": cve.get("published", ""),
            "modified":  cve.get("lastModified", "")}


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 3 — parse_cwe
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Parse MITRE CWE XML content into structured records. "
        "Returns list of CWE dicts with id, name, status, abstraction, description, "
        "consequences, capec_refs."
    ),
    params={"xml_content": {"type": "string", "description": "Raw CWE XML string"}},
)
def parse_cwe(xml_content: str) -> list[dict]:
    import xml.etree.ElementTree as ET
    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
    root = ET.fromstring(xml_content)
    out = []
    for w in root.findall(".//cwe:Weakness", ns):
        cwe_id   = f"CWE-{w.attrib['ID']}"
        name     = w.attrib.get("Name", "")
        status   = w.attrib.get("Status", "")
        abstr    = w.attrib.get("Abstraction", "")

        desc_el = w.find("cwe:Description", ns)
        desc     = (desc_el.text or "").strip() if desc_el is not None else ""

        # common consequences
        consequences = []
        for cons in w.findall(".//cwe:Common_Consequences/cwe:Consequence", ns):
            scope_els = cons.findall("cwe:Scope", ns)
            impact_els = cons.findall("cwe:Impact", ns)
            scopes  = [s.text for s in scope_els if s.text]
            impacts = [i.text for i in impact_els if i.text]
            consequences.append({"scopes": scopes, "impacts": impacts})

        # related CAPEC IDs
        capec_refs = []
        for rel in w.findall(".//cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern", ns):
            capec_refs.append(f"CAPEC-{rel.attrib['CAPEC_ID']}")

        out.append({"id": cwe_id, "name": name, "status": status,
                    "abstraction": abstr, "description": desc,
                    "consequences": consequences, "capec_refs": capec_refs})

    log.info(f"[parse_cwe] parsed {len(out)} CWEs")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 4 — parse_capec
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Parse MITRE CAPEC XML into structured records. "
        "Returns list of dicts with id, name, abstraction, status, description, "
        "mitigations, prerequisites, cwe_refs."
    ),
    params={"xml_content": {"type": "string", "description": "Raw CAPEC XML string"}},
)
def parse_capec(xml_content: str) -> list[dict]:
    import xml.etree.ElementTree as ET
    ns = {"capec": "http://capec.mitre.org/capec-3"}
    root = ET.fromstring(xml_content)
    out = []
    for ap in root.findall(".//capec:Attack_Pattern", ns):
        capec_id   = f"CAPEC-{ap.attrib['ID']}"
        name       = ap.attrib.get("Name", "")
        abstraction = ap.attrib.get("Abstraction", "")
        status      = ap.attrib.get("Status", "")

        desc_el = ap.find("capec:Description", ns)
        desc    = (desc_el.text or "").strip() if desc_el is not None else ""

        # mitigations
        mitigations = []
        for m in ap.findall(".//capec:Solution_or_Mitigation", ns):
            if m.text:
                mitigations.append(m.text.strip())

        # prerequisites
        prereqs = []
        for p in ap.findall(".//capec:Prerequisite", ns):
            if p.text:
                prereqs.append(p.text.strip())

        # related CWEs
        cwe_refs = []
        for rel in ap.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", ns):
            cwe_refs.append(f"CWE-{rel.attrib['CWE_ID']}")

        out.append({"id": capec_id, "name": name, "abstraction": abstraction,
                    "status": status, "description": desc,
                    "mitigations": mitigations, "prerequisites": prereqs,
                    "cwe_refs": cwe_refs})

    log.info(f"[parse_capec] parsed {len(out)} CAPECs")
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 5 — convert_to_rdf
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Convert parsed records into RDF triples using the SEPSES CSKG ontology. "
        "source_type: 'cve' | 'cwe' | 'capec'. "
        "Returns {'triples': int, 'graph_file': str} path to .ttl."
    ),
    params={
        "records": {"type": "array",  "description": "List of parsed dicts from a parse_* tool",
                    "items": {"type": "object"}},
        "source_type": {"type": "string", "description": "One of: cve, cwe, capec"},
        "output_file": {"type": "string", "description": "Output .ttl filename (in output/)"},
    },
)
def convert_to_rdf(records: list[dict], source_type: str, output_file: str) -> dict:
    g = Graph()
    # bind all prefixes
    g.bind("cve",   CVE_NS)
    g.bind("cwe",   CWE_NS)
    g.bind("cvss",  CVSS)
    g.bind("capec", CAPEC)
    g.bind("cpe",   CPE_NS)
    g.bind("att",   ATT)
    g.bind("dct",   DCTERMS)
    g.bind("r_cve", R_CVE)
    g.bind("r_cwe", R_CWE)
    g.bind("r_cpe", R_CPE)
    g.bind("r_capec", R_CAPEC)

    if source_type == "cve":
        for r in records:
            _cve_to_rdf(g, r)
    elif source_type == "cwe":
        for r in records:
            _cwe_to_rdf(g, r)
    elif source_type == "capec":
        for r in records:
            _capec_to_rdf(g, r)
    else:
        raise ValueError(f"Unknown source_type: {source_type}")

    out_path = OUTPUT_DIR / output_file
    g.serialize(destination=str(out_path), format="turtle")
    log.info(f"[convert_to_rdf] {source_type}: {len(g)} triples → {out_path}")
    return {"triples": len(g), "graph_file": str(out_path)}


def _cve_to_rdf(g: Graph, r: dict):
    uri = cve_uri(r["id"])
    g.add((uri, RDF.type,        CVEVocab.CVE))
    g.add((uri, CVEVocab.id,     Literal(r["id"])))
    if r.get("description"):
        g.add((uri, DCTERMS.description, Literal(r["description"])))
    if r.get("published"):
        g.add((uri, DCTERMS.issued,   Literal(r["published"])))
    if r.get("modified"):
        g.add((uri, DCTERMS.modified, Literal(r["modified"])))

    for cpe_str in r.get("cpes", []):
        if cpe_str:
            g.add((uri, CVEVocab.hasCPE, URIRef(cpe_uri(cpe_str))))

    for cwe_str in r.get("cwes", []):
        if cwe_str and cwe_str.startswith("CWE-"):
            g.add((uri, CVEVocab.hasCWE, cwe_uri(cwe_str)))

    # CVSS2
    if r.get("cvss2"):
        m = r["cvss2"]
        metric_uri = URIRef(str(uri) + "_cvss2")
        g.add((uri, CVEVocab.hasCVSS2, metric_uri))
        g.add((metric_uri, RDF.type, CVSSVocab.CVSS2BaseMetric))
        _add_cvss(g, metric_uri, m)

    # CVSS3
    if r.get("cvss3"):
        m = r["cvss3"]
        metric_uri = URIRef(str(uri) + "_cvss3")
        g.add((uri, CVEVocab.hasCVSS3, metric_uri))
        g.add((metric_uri, RDF.type, CVSSVocab.CVSS3BaseMetric))
        _add_cvss(g, metric_uri, m)


def _add_cvss(g: Graph, uri: URIRef, m: dict):
    for prop, key in [
        (CVSSVocab.baseScore,             "baseScore"),
        (CVSSVocab.vectorString,          "vectorString"),
        (CVSSVocab.confidentialityImpact, "confidentialityImpact"),
        (CVSSVocab.integrityImpact,       "integrityImpact"),
        (CVSSVocab.availabilityImpact,    "availabilityImpact"),
        (CVSSVocab.attackComplexity,      "attackComplexity"),
    ]:
        if m.get(key) is not None:
            val = m[key]
            lit = Literal(float(val), datatype=XSD.decimal) if key == "baseScore" else Literal(str(val))
            g.add((uri, prop, lit))


def _cwe_to_rdf(g: Graph, r: dict):
    uri = cwe_uri(r["id"])
    g.add((uri, RDF.type,     CWEVocab.Weakness))
    g.add((uri, CWEVocab.name,   Literal(r["name"])))
    g.add((uri, CWEVocab.status, Literal(r["status"])))
    if r.get("abstraction"):
        g.add((uri, CWEVocab.abstraction, Literal(r["abstraction"])))
    if r.get("description"):
        g.add((uri, DCTERMS.description, Literal(r["description"])))

    for capec_id in r.get("capec_refs", []):
        g.add((uri, CWEVocab.hasCAPEC, capec_uri(capec_id)))

    for i, cons in enumerate(r.get("consequences", [])):
        cons_uri = URIRef(str(uri) + f"_consequence_{i}")
        g.add((uri, CWEVocab.hasCommonConsequence, cons_uri))
        for scope in cons.get("scopes", []):
            g.add((cons_uri, CWEVocab.consequenceScope, Literal(scope)))
        for impact in cons.get("impacts", []):
            g.add((cons_uri, CWEVocab.consequenceImpact, Literal(impact)))


def _capec_to_rdf(g: Graph, r: dict):
    uri = capec_uri(r["id"])
    g.add((uri, RDF.type, CAPECVocab.AttackPattern))
    g.add((uri, CAPECVocab.name, Literal(r["name"])))
    if r.get("abstraction"):
        g.add((uri, CAPECVocab.abstraction, Literal(r["abstraction"])))
    if r.get("status"):
        g.add((uri, CAPECVocab.status, Literal(r["status"])))
    if r.get("description"):
        g.add((uri, DCTERMS.description, Literal(r["description"])))

    for mit in r.get("mitigations", []):
        g.add((uri, CAPECVocab.mitigation, Literal(mit)))
    for pre in r.get("prerequisites", []):
        g.add((uri, CAPECVocab.prerequisite, Literal(pre)))
    for cwe_id in r.get("cwe_refs", []):
        g.add((uri, CAPECVocab.hasCWE, cwe_uri(cwe_id)))


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 6 — link_graphs
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Load two Turtle graphs from disk, discover cross-source links by shared "
        "identifiers, and emit a link graph .ttl. "
        "link_type: 'cve-cwe' | 'cwe-capec' | 'cve-capec'. "
        "Returns {'links_added': int, 'link_file': str}."
    ),
    params={
        "graph_a_file": {"type": "string", "description": "Path to first .ttl file"},
        "graph_b_file": {"type": "string", "description": "Path to second .ttl file"},
        "link_type":    {"type": "string", "description": "cve-cwe | cwe-capec | cve-capec"},
        "output_file":  {"type": "string", "description": "Output .ttl filename"},
    },
)
def link_graphs(graph_a_file: str, graph_b_file: str,
                link_type: str, output_file: str) -> dict:
    ga = Graph()
    ga.parse(graph_a_file, format="turtle")
    gb = Graph()
    gb.parse(graph_b_file, format="turtle")

    link_g = Graph()
    link_g.bind("cve",   CVE_NS)
    link_g.bind("cwe",   CWE_NS)
    link_g.bind("capec", CAPEC)

    count = 0

    if link_type == "cve-cwe":
        # CVE hasCWE → verify CWE exists in cwe graph
        cwe_uris = set(s for s in gb.subjects(RDF.type, CWEVocab.Weakness))
        for cve, _, cwe in ga.triples((None, CVEVocab.hasCWE, None)):
            if cwe in cwe_uris:
                link_g.add((cve, CVEVocab.hasCWE, cwe))
                count += 1

    elif link_type == "cwe-capec":
        # CWE hasCAPEC → verify CAPEC exists in capec graph
        capec_uris = set(s for s in gb.subjects(RDF.type, CAPECVocab.AttackPattern))
        for cwe_s, _, capec in ga.triples((None, CWEVocab.hasCAPEC, None)):
            if capec in capec_uris:
                link_g.add((cwe_s, CWEVocab.hasCAPEC, capec))
                count += 1
        # CAPEC hasCWE reverse
        for capec_s, _, cwe in gb.triples((None, CAPECVocab.hasCWE, None)):
            cwe_uris = set(s for s in ga.subjects(RDF.type, CWEVocab.Weakness))
            if cwe in cwe_uris:
                link_g.add((capec_s, CAPECVocab.hasCWE, cwe))
                count += 1

    elif link_type == "cve-capec":
        # Transitive: cve → cwe → capec (materialise shortcut)
        cwe_capec: dict[URIRef, list[URIRef]] = {}
        for cwe_s, _, capec in gb.triples((None, CWEVocab.hasCAPEC, None)):
            cwe_capec.setdefault(cwe_s, []).append(capec)
        for cve, _, cwe in ga.triples((None, CVEVocab.hasCWE, None)):
            for capec in cwe_capec.get(cwe, []):
                link_g.add((cve, CVEVocab.hasCWE, cwe))       # keep chain
                link_g.add((cwe, CWEVocab.hasCAPEC, capec))
                count += 1

    out_path = OUTPUT_DIR / output_file
    link_g.serialize(destination=str(out_path), format="turtle")
    log.info(f"[link_graphs] {link_type}: {count} links → {out_path}")
    return {"links_added": count, "link_file": str(out_path)}


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 7 — validate_graph
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Validate a Turtle graph against SEPSES SHACL-style constraints. "
        "Checks: required properties, datatype correctness, URI patterns. "
        "Returns {'valid': bool, 'violations': list[str], 'triples': int}."
    ),
    params={
        "graph_file":  {"type": "string", "description": "Path to .ttl to validate"},
        "source_type": {"type": "string", "description": "cve | cwe | capec"},
    },
)
def validate_graph(graph_file: str, source_type: str) -> dict:
    g = Graph()
    g.parse(graph_file, format="turtle")
    violations = []

    if source_type == "cve":
        for cve in g.subjects(RDF.type, CVEVocab.CVE):
            ids = list(g.objects(cve, CVEVocab.id))
            if len(ids) != 1:
                violations.append(f"{cve}: must have exactly 1 cve:id, found {len(ids)}")
            else:
                if not str(ids[0]).startswith("CVE-"):
                    violations.append(f"{cve}: cve:id '{ids[0]}' doesn't match CVE-YYYY-NNNNN")
            if not str(cve).startswith("http://w3id.org/sepses/resource/cve/"):
                violations.append(f"CVE URI pattern violation: {cve}")

    elif source_type == "cwe":
        for cwe_s in g.subjects(RDF.type, CWEVocab.Weakness):
            names = list(g.objects(cwe_s, CWEVocab.name))
            if len(names) < 1:
                violations.append(f"{cwe_s}: missing required cwe:name")
            if not str(cwe_s).startswith("http://w3id.org/sepses/resource/cwe/"):
                violations.append(f"CWE URI pattern violation: {cwe_s}")

    elif source_type == "capec":
        for ap in g.subjects(RDF.type, CAPECVocab.AttackPattern):
            names = list(g.objects(ap, CAPECVocab.name))
            if len(names) < 1:
                violations.append(f"{ap}: missing required capec:name")
            if not str(ap).startswith("http://w3id.org/sepses/resource/capec/"):
                violations.append(f"CAPEC URI pattern violation: {ap}")

    valid = len(violations) == 0
    log.info(f"[validate_graph] {source_type}: valid={valid}, violations={len(violations)}")
    return {"valid": valid, "violations": violations[:20], "triples": len(g)}


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 8 — merge_graphs
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Merge multiple Turtle files into a single combined .ttl (the final KG). "
        "Returns {'total_triples': int, 'merged_file': str}."
    ),
    params={
        "input_files": {"type": "array",  "description": "List of .ttl file paths to merge",
                        "items": {"type": "string"}},
        "output_file": {"type": "string", "description": "Output merged .ttl filename"},
    },
)
def merge_graphs(input_files: list[str], output_file: str) -> dict:
    merged = Graph()
    merged.bind("cve",   CVE_NS)
    merged.bind("cwe",   CWE_NS)
    merged.bind("cvss",  CVSS)
    merged.bind("capec", CAPEC)
    merged.bind("cpe",   CPE_NS)
    merged.bind("dct",   DCTERMS)

    for f in input_files:
        if Path(f).exists():
            merged.parse(f, format="turtle")
            log.info(f"[merge_graphs] merged {f}")
        else:
            log.warning(f"[merge_graphs] file not found: {f}")

    out_path = OUTPUT_DIR / output_file
    merged.serialize(destination=str(out_path), format="turtle")
    log.info(f"[merge_graphs] final KG: {len(merged)} triples → {out_path}")
    return {"total_triples": len(merged), "merged_file": str(out_path)}


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 9 — sparql_query
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Run a SPARQL SELECT query against a local Turtle file. "
        "Returns list of result rows as dicts. Use to verify KG correctness."
    ),
    params={
        "graph_file": {"type": "string", "description": "Path to .ttl to query"},
        "query":      {"type": "string", "description": "SPARQL SELECT query string"},
    },
)
def sparql_query(graph_file: str, query: str) -> list[dict]:
    g = Graph()
    g.parse(graph_file, format="turtle")
    results = g.query(query)
    out = []
    for row in results:
        out.append({str(k): str(v) for k, v in zip(results.vars, row)})
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL 10 — report_stats
# ═══════════════════════════════════════════════════════════════════════════════
@tool(
    description=(
        "Generate a statistics report for a Turtle KG file: "
        "counts by class, property, and named graph. "
        "Returns a markdown-formatted string."
    ),
    params={
        "graph_file": {"type": "string", "description": "Path to .ttl file"},
    },
)
def report_stats(graph_file: str) -> str:
    g = Graph()
    g.parse(graph_file, format="turtle")

    class_counts: dict[str, int] = {}
    for _, _, cls in g.triples((None, RDF.type, None)):
        c = str(cls).split("#")[-1].split("/")[-1]
        class_counts[c] = class_counts.get(c, 0) + 1

    lines = [f"## KG Statistics: {Path(graph_file).name}",
             f"**Total triples**: {len(g)}", "",
             "### Instances by class"]
    for cls, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        lines.append(f"- `{cls}`: {cnt}")

    return "\n".join(lines)
