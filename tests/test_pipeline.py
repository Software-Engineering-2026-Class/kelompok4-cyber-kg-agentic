"""
tests/test_pipeline.py

Unit tests for every tool and ontology mapping.
Run with:  python -m pytest tests/ -v
"""

import json
import sys
import pytest
from pathlib import Path

# make project root importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from rdflib import Graph, URIRef, Literal
from rdflib.namespace import RDF, DCTERMS

from ontology.namespaces import (
    CVEVocab, CVSSVocab, CWEVocab, CAPECVocab,
    cve_uri, cwe_uri, capec_uri, cpe_uri,
    R_CVE, R_CWE, R_CAPEC,
    CVE_NS, CWE_NS, CVSS, CAPEC,
)
from tools.tools import (
    parse_cve, parse_cwe, parse_capec,
    convert_to_rdf, link_graphs, validate_graph,
    merge_graphs, sparql_query, report_stats,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_CVE_JSON = json.dumps({
    "CVE_Items": [
        {
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2021-44228"},
                "description": {"description_data": [
                    {"lang": "en", "value": "Log4Shell RCE vulnerability"}
                ]},
                "problemtype": {"problemtype_data": [
                    {"description": [{"value": "CWE-502"}]}
                ]},
            },
            "configurations": {"nodes": [
                {"cpe_match": [
                    {"vulnerable": True, "cpe23Uri": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                ]}
            ]},
            "impact": {
                "baseMetricV2": {
                    "cvssV2": {
                        "baseScore": 9.3,
                        "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "accessVector": "NETWORK",
                        "confidentialityImpact": "COMPLETE",
                        "integrityImpact": "COMPLETE",
                        "availabilityImpact": "COMPLETE",
                    }
                }
            },
            "publishedDate": "2021-12-10T10:15Z",
            "lastModifiedDate": "2021-12-14T00:00Z",
        }
    ]
})

SAMPLE_CWE_XML = """<?xml version="1.0"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="502" Name="Deserialization of Untrusted Data" Status="Stable" Abstraction="Base">
      <Description>The application deserializes untrusted data.</Description>
      <Common_Consequences>
        <Consequence>
          <Scope>Integrity</Scope>
          <Impact>Execute Unauthorized Code or Commands</Impact>
        </Consequence>
      </Common_Consequences>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="586"/>
      </Related_Attack_Patterns>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

SAMPLE_CAPEC_XML = """<?xml version="1.0"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="586" Name="Object Injection" Abstraction="Standard" Status="Draft">
      <Description>Attackers inject malicious objects.</Description>
      <Solutions_and_Mitigations>
        <Solution_or_Mitigation>Validate all deserialized data.</Solution_or_Mitigation>
      </Solutions_and_Mitigations>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="502"/>
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


# ── Ontology URI helpers ───────────────────────────────────────────────────────

def test_cve_uri():
    uri = cve_uri("CVE-2021-44228")
    assert str(uri) == "http://w3id.org/sepses/resource/cve/CVE-2021-44228"

def test_cwe_uri():
    uri = cwe_uri("502")
    assert str(uri) == "http://w3id.org/sepses/resource/cwe/CWE-502"
    uri2 = cwe_uri("CWE-502")
    assert uri == uri2

def test_capec_uri():
    uri = capec_uri("586")
    assert str(uri) == "http://w3id.org/sepses/resource/capec/CAPEC-586"

def test_cpe_uri():
    # should produce lowercase, no separators
    uri = cpe_uri("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert uri.startswith("http://w3id.org/sepses/resource/cpe/")
    # verify no colons/dots/stars left after prefix
    suffix = uri.replace("http://w3id.org/sepses/resource/cpe/", "")
    assert ":" not in suffix
    assert "." not in suffix


# ── Parser tests ──────────────────────────────────────────────────────────────

def test_parse_cve():
    records = parse_cve(SAMPLE_CVE_JSON)
    assert len(records) == 1
    r = records[0]
    assert r["id"] == "CVE-2021-44228"
    assert "Log4Shell" in r["description"]
    assert "CWE-502" in r["cwes"]
    assert any("log4j" in c for c in r["cpes"])
    assert r["cvss2"] is not None
    assert r["cvss2"]["baseScore"] == 9.3

def test_parse_cwe():
    records = parse_cwe(SAMPLE_CWE_XML)
    assert len(records) == 1
    r = records[0]
    assert r["id"] == "CWE-502"
    assert r["name"] == "Deserialization of Untrusted Data"
    assert r["status"] == "Stable"
    assert "CAPEC-586" in r["capec_refs"]
    assert len(r["consequences"]) == 1

def test_parse_capec():
    records = parse_capec(SAMPLE_CAPEC_XML)
    assert len(records) == 1
    r = records[0]
    assert r["id"] == "CAPEC-586"
    assert r["name"] == "Object Injection"
    assert "CWE-502" in r["cwe_refs"]
    assert len(r["mitigations"]) == 1


# ── RDF conversion tests ─────────────────────────────────────────────────────

def test_convert_cve_to_rdf(tmp_path):
    records = parse_cve(SAMPLE_CVE_JSON)

    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path

    result = convert_to_rdf(records, "cve", "test_cve.ttl")
    assert result["triples"] > 0

    g = Graph()
    g.parse(str(tmp_path / "test_cve.ttl"), format="turtle")

    # check CVE instance
    cve = cve_uri("CVE-2021-44228")
    assert (cve, RDF.type, CVEVocab.CVE) in g

    # check id literal
    ids = list(g.objects(cve, CVEVocab.id))
    assert len(ids) == 1 and str(ids[0]) == "CVE-2021-44228"

    # check CWE link
    assert (cve, CVEVocab.hasCWE, cwe_uri("CWE-502")) in g

    # check CVSS
    cvss_nodes = list(g.objects(cve, CVEVocab.hasCVSS2))
    assert len(cvss_nodes) == 1
    scores = list(g.objects(cvss_nodes[0], CVSSVocab.baseScore))
    assert len(scores) == 1
    assert float(str(scores[0])) == 9.3


def test_convert_cwe_to_rdf(tmp_path):
    records = parse_cwe(SAMPLE_CWE_XML)
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path
    result = convert_to_rdf(records, "cwe", "test_cwe.ttl")
    assert result["triples"] > 0

    g = Graph()
    g.parse(str(tmp_path / "test_cwe.ttl"), format="turtle")
    cwe = cwe_uri("CWE-502")
    assert (cwe, RDF.type, CWEVocab.Weakness) in g
    names = list(g.objects(cwe, CWEVocab.name))
    assert any("Deserialization" in str(n) for n in names)


def test_convert_capec_to_rdf(tmp_path):
    records = parse_capec(SAMPLE_CAPEC_XML)
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path
    result = convert_to_rdf(records, "capec", "test_capec.ttl")
    assert result["triples"] > 0

    g = Graph()
    g.parse(str(tmp_path / "test_capec.ttl"), format="turtle")
    ap = capec_uri("CAPEC-586")
    assert (ap, RDF.type, CAPECVocab.AttackPattern) in g


# ── Validation tests ──────────────────────────────────────────────────────────

def test_validate_cve_pass(tmp_path):
    records = parse_cve(SAMPLE_CVE_JSON)
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path
    convert_to_rdf(records, "cve", "v_cve.ttl")
    r = validate_graph(str(tmp_path / "v_cve.ttl"), "cve")
    assert r["valid"] is True
    assert r["violations"] == []

def test_validate_cwe_pass(tmp_path):
    records = parse_cwe(SAMPLE_CWE_XML)
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path
    convert_to_rdf(records, "cwe", "v_cwe.ttl")
    r = validate_graph(str(tmp_path / "v_cwe.ttl"), "cwe")
    assert r["valid"] is True


# ── Linking tests ─────────────────────────────────────────────────────────────

def test_link_cwe_capec(tmp_path):
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path

    cwe_records   = parse_cwe(SAMPLE_CWE_XML)
    capec_records = parse_capec(SAMPLE_CAPEC_XML)
    convert_to_rdf(cwe_records,   "cwe",   "lnk_cwe.ttl")
    convert_to_rdf(capec_records, "capec", "lnk_capec.ttl")

    result = link_graphs(
        str(tmp_path / "lnk_cwe.ttl"),
        str(tmp_path / "lnk_capec.ttl"),
        "cwe-capec",
        "lnk_cwe_capec.ttl",
    )
    assert result["links_added"] > 0


# ── Merge + SPARQL tests ──────────────────────────────────────────────────────

def test_merge_and_sparql(tmp_path):
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path

    cve_r   = parse_cve(SAMPLE_CVE_JSON)
    cwe_r   = parse_cwe(SAMPLE_CWE_XML)
    capec_r = parse_capec(SAMPLE_CAPEC_XML)

    convert_to_rdf(cve_r,   "cve",   "m_cve.ttl")
    convert_to_rdf(cwe_r,   "cwe",   "m_cwe.ttl")
    convert_to_rdf(capec_r, "capec", "m_capec.ttl")

    merged = merge_graphs(
        [str(tmp_path / "m_cve.ttl"),
         str(tmp_path / "m_cwe.ttl"),
         str(tmp_path / "m_capec.ttl")],
        "merged.ttl",
    )
    assert merged["total_triples"] > 0

    rows = sparql_query(
        str(tmp_path / "merged.ttl"),
        """PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
           SELECT (COUNT(?x) AS ?n) WHERE { ?x a cve:CVE }"""
    )
    assert rows[0]["n"] == "1"

def test_report_stats(tmp_path):
    import tools.tools as tt
    tt.OUTPUT_DIR = tmp_path
    records = parse_cve(SAMPLE_CVE_JSON)
    convert_to_rdf(records, "cve", "stat_cve.ttl")
    report = report_stats(str(tmp_path / "stat_cve.ttl"))
    assert "Total triples" in report
    assert "CVE" in report
