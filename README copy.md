# Cyber-KG Agentic Pipeline

A Python reimagining of the [SEPSES Cyber-KB Engine](https://github.com/sepses/cyber-kg-converter)
where an **AI agent** (Claude) plans and executes the entire knowledge graph construction
pipeline dynamically at runtime — deciding how to parse, link, and validate data
using tools, rather than following a hard-coded sequence.

## What it does

Produces a **SEPSES-compatible Cybersecurity Knowledge Graph (CSKG)** in Turtle/RDF,
fully compatible with the original schema and ontology, by:

1. Fetching CVE, CWE, and CAPEC data from public sources
2. Parsing each format (JSON, XML) into structured records
3. Converting to RDF using the **exact SEPSES CSKG ontology** (`w3id.org/sepses/vocab/ref/*`)
4. Cross-linking entities (CVE → CWE → CAPEC) using shared identifiers
5. Validating RDF against SHACL-style constraints
6. Merging into a unified `.ttl` knowledge graph
7. Running SPARQL verification queries
8. Reporting final statistics

## Ontology Fidelity

All URIs and predicates match the original SEPSES CSKG exactly:

| Source | Instance URI pattern | Key predicates |
|--------|---------------------|----------------|
| CVE    | `http://w3id.org/sepses/resource/cve/{ID}` | `cve:id`, `cve:hasCWE`, `cve:hasCPE`, `cve:hasCVSS2BaseMetric` |
| CWE    | `http://w3id.org/sepses/resource/cwe/{ID}` | `cwe:name`, `cwe:hasCAPEC`, `cwe:hasCommonConsequence` |
| CAPEC  | `http://w3id.org/sepses/resource/capec/{ID}` | `capec:name`, `capec:mitigation`, `capec:hasCWE` |
| CPE    | `http://w3id.org/sepses/resource/cpe/{norm}` | `cpe:vendor`, `cpe:product` |

## Architecture

```
main.py
  └── CyberKGAgent  (agent.py)
        │  Uses Claude as reasoning engine
        │  Agentic loop: plan → tool_call → observe → repeat
        └── Tools (tools/tools.py)
              ├── fetch_source      — HTTP download + zip extraction
              ├── parse_cve         — NVD JSON 1.1 / 2.0 parser
              ├── parse_cwe         — MITRE CWE XML parser
              ├── parse_capec       — MITRE CAPEC XML parser
              ├── convert_to_rdf    — records → RDF (SEPSES ontology)
              ├── link_graphs       — cross-source RDF linking
              ├── validate_graph    — SHACL-style constraint checks
              ├── merge_graphs      — combine multiple .ttl files
              ├── sparql_query      — run SPARQL against local .ttl
              └── report_stats      — class/property count report
```

## Why Agentic?

The original Java engine uses hard-coded RML mappings and a fixed execution order.
This pipeline replaces that with an **AI agent that reasons about each step**:

- Decides which sources to fetch and in what order
- Adapts if a URL fails (tries fallbacks)
- Diagnoses validation failures and decides whether to retry
- Chooses when cross-source linking is complete
- Writes its own SPARQL verification queries

The KG output format and ontology remain identical to SEPSES CSKG.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
# Full pipeline (fetches ~200 CVEs + all CWEs + all CAPECs)
python main.py

# Dry-run: print available tools and exit
python main.py --dry-run

# Custom goal
python main.py --goal "Build a KG with only CVE and CWE data, no CAPEC"

# Verbose debug logging
python main.py --verbose
```

## Output

All files are written to `output/`:

| File | Contents |
|------|----------|
| `cve.ttl` | CVE RDF graph |
| `cwe.ttl` | CWE RDF graph |
| `capec.ttl` | CAPEC RDF graph |
| `link_cve_cwe.ttl` | CVE→CWE link graph |
| `link_cwe_capec.ttl` | CWE→CAPEC link graph |
| `cskg_final.ttl` | **Merged CSKG** (query this) |
| `agent.log` | Full agent trace |

## Run Tests

```bash
python -m pytest tests/ -v
```

15 tests covering: URI generation, all parsers, RDF conversion,
validation, linking, merging, SPARQL, and reporting.

## References

- Kiesling et al. (2019) — *The SEPSES Knowledge Graph: An Integrated Resource for Cybersecurity* (ISWC)
- Kurniawan et al. (2021) — *An ATT&CK-KG for Linking Cybersecurity Attacks to Adversary Tactics*
- Original engine: https://github.com/sepses/cyber-kg-converter
- SEPSES SPARQL endpoint: https://w3id.org/sepses/sparql
