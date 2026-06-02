import json
import traceback
from pathlib import Path
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF
from ..state import ParserState
from ..parsers.json_parser import JSONParser
from ..parsers.xml_parser import XMLParser
from ..ontology_mapper import OntologyMapper

# Namespace base untuk setiap source
VOCAB_NS = {
    "cve":              "http://w3id.org/sepses/vocab/ref/cve#",
    "cwe":              "http://w3id.org/sepses/vocab/ref/cwe#",
    "cpe":              "http://w3id.org/sepses/vocab/ref/cpe#",
    "capec":            "http://w3id.org/sepses/vocab/ref/capec#",
    "icsa":             "http://w3id.org/sepses/vocab/ref/icsa#",
    "attck_enterprise": "http://w3id.org/sepses/vocab/ref/attack#",
    "attck_ics":        "http://w3id.org/sepses/vocab/ref/attack#",
}

RESOURCE_BASE = "http://w3id.org/sepses/resource/"

def build_subject_uri(source_key: str, entity_id: str, mapped: dict = None) -> str:
    if source_key.startswith("attck"):
        # Prioritaskan techniqueId sebagai URI supaya cocok dengan linking_agent
        uri_key = mapped.get("__uri_key__") if mapped else None
        if uri_key:
            return f"{RESOURCE_BASE}attack/{uri_key}"
        # Fallback ke UUID kalau tidak ada techniqueId
        slug = entity_id.replace("attack-pattern--", "")
        return f"{RESOURCE_BASE}attack/{slug}"
    return f"{RESOURCE_BASE}{source_key}/{entity_id}"

def executor(state: ParserState) -> ParserState:
    task = state.get("current_task")
    if not task:
        print("  [EXECUTOR] No task to execute.")
        parsed_results = state.get("parsed_results", [])
        parse_plan = state.get("parse_plan", [])
        next_task = parse_plan.pop(0) if parse_plan else {}
        return {
            "parse_plan": parse_plan,
            "current_task": next_task,
            "parsed_results": parsed_results
        }

    source = task["source"]
    file_path = task["file_path"]
    parser_type = task["parser_type"]

    print(f"  [EXECUTOR] Parsing {source} using {parser_type} parser...")

    result = {
        "source": source,
        "status": "failed",
        "entities_count": 0,
        "error": None,
        "output_file": None
    }

    try:
        # 1. Parse raw data
        if parser_type == "json":
            parser = JSONParser(source, file_path)
        elif parser_type == "xml":
            parser = XMLParser(source, file_path)
        else:
            raise ValueError(f"Unknown parser type: {parser_type}")

        raw_entities = parser.parse()
        print(f"  [EXECUTOR] Extracted {len(raw_entities)} raw entities from {source}.")

        # 2. Generate RML rules (tetap dipertahankan sebagai dokumentasi mapping)
        source_key = source.lower()
        # ... (blok RML tidak diubah, langsung lanjut ke simpan)
        out_dir = Path("parser_agent/output")
        out_dir.mkdir(parents=True, exist_ok=True)

        # [blok rml_content yang lama tetap di sini, tidak perlu dihapus]
        # out_file = out_dir / f"{source}.rml"
        # with open(out_file, "w", encoding="utf-8") as f:
        #     f.write(rml_content)

        # 3. Map entitas ke ontologi SEPSES dan bangun RDF graph
        mapper = OntologyMapper()
        vocab_uri = VOCAB_NS.get(source_key, f"http://w3id.org/sepses/vocab/ref/{source_key}#")
        SEPSES = Namespace(vocab_uri)
        g = Graph()
        g.bind(source_key if not source_key.startswith("attck") else "attck", SEPSES)

        skipped = 0
        for entity in raw_entities:
            mapped = mapper.map_entity(source, entity)
            if not mapped:
                skipped += 1
                continue

            # Ambil entity_id — tiap source punya field identifier yang berbeda
            entity_id = (
                mapped.get("sepses:id") or
                mapped.get("sepses:cveID") or    # fallback untuk ICSA
                mapped.get("sepses:cpe23Uri")    # fallback untuk CPE kalau perlu
            )
            if not entity_id:
                skipped += 1
                continue

            subject = URIRef(build_subject_uri(source_key, str(entity_id), mapped))

            # rdf:type
            rdf_type = mapped.get("@type", "").replace("sepses:", "")
            if rdf_type:
                g.add((subject, RDF.type, SEPSES[rdf_type]))

            # properti lainnya
            for key, value in mapped.items():
                if key.startswith("@") or not key.startswith("sepses:"):
                    continue
                pred_name = key.replace("sepses:", "")
                if isinstance(value, list):
                    for v in value:
                        if v:
                            g.add((subject, SEPSES[pred_name], Literal(str(v))))
                else:
                    g.add((subject, SEPSES[pred_name], Literal(str(value))))

        print(f"  [EXECUTOR] Built RDF graph: {len(g)} triples ({skipped} entities skipped).")

        # 4. Serialize ke TTL
        out_ttl = out_dir / f"{source}.ttl"
        g.serialize(destination=str(out_ttl), format="turtle")
        print(f"  [EXECUTOR] TTL saved to {out_ttl}.")

        result["status"] = "success"
        result["entities_count"] = len(raw_entities) - skipped
        result["output_file"] = str(out_ttl)

    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"  [EXECUTOR] Error processing {source}: {error_msg}")
        result["error"] = str(e)

    parsed_results = state.get("parsed_results", [])
    parsed_results.append(result)

    parse_plan = state.get("parse_plan", [])
    next_task = parse_plan.pop(0) if parse_plan else {}

    return {
        "parse_plan": parse_plan,
        "current_task": next_task,
        "parsed_results": parsed_results
    }