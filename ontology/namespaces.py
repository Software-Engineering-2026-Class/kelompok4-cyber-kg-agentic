"""
SEPSES CSKG Ontology Namespaces
Matches exactly the vocabularies defined in:
  - http://w3id.org/sepses/vocab/ref/cve
  - http://w3id.org/sepses/vocab/ref/cwe
  - http://w3id.org/sepses/vocab/ref/capec
  - http://w3id.org/sepses/vocab/ref/cvss
  - http://w3id.org/sepses/vocab/ref/cpe
  - http://w3id.org/sepses/vocab/ref/attack  (ATT&CK extension, Kurniawan et al. 2021)
"""

from rdflib import Namespace, URIRef

# ── Vocabulary namespaces ──────────────────────────────────────────────────────
CAPEC  = Namespace("http://w3id.org/sepses/vocab/ref/capec#")
CWE_NS = Namespace("http://w3id.org/sepses/vocab/ref/cwe#")
CVE_NS = Namespace("http://w3id.org/sepses/vocab/ref/cve#")
CVSS   = Namespace("http://w3id.org/sepses/vocab/ref/cvss#")
CPE_NS = Namespace("http://w3id.org/sepses/vocab/ref/cpe#")
ATT    = Namespace("http://w3id.org/sepses/vocab/ref/attack#")

# ── Resource (instance) namespaces ────────────────────────────────────────────
R_CVE   = Namespace("http://w3id.org/sepses/resource/cve/")
R_CWE   = Namespace("http://w3id.org/sepses/resource/cwe/")
R_CPE   = Namespace("http://w3id.org/sepses/resource/cpe/")
R_CAPEC = Namespace("http://w3id.org/sepses/resource/capec/")
R_ATT   = Namespace("http://w3id.org/sepses/resource/attack/")

# ── Named graphs ──────────────────────────────────────────────────────────────
GRAPH_CVE   = URIRef("http://w3id.org/sepses/graph/cve")
GRAPH_CWE   = URIRef("http://w3id.org/sepses/graph/cwe")
GRAPH_CPE   = URIRef("http://w3id.org/sepses/graph/cpe")
GRAPH_CAPEC = URIRef("http://w3id.org/sepses/graph/capec")
GRAPH_ATT   = URIRef("http://w3id.org/sepses/graph/attack")

# ── Standard namespaces used in mappings ──────────────────────────────────────
from rdflib.namespace import RDF, RDFS, OWL, XSD, DCTERMS

# ── CVE class & property URIs (cve vocab) ─────────────────────────────────────
class CVEVocab:
    CVE         = CVE_NS.CVE
    id          = CVE_NS.id
    description = CVE_NS.description
    hasCPE      = CVE_NS.hasCPE
    hasCWE      = CVE_NS.hasCWE
    hasCVSS2    = CVE_NS["hasCVSS2BaseMetric"]
    hasCVSS3    = CVE_NS["hasCVSS3BaseMetric"]

# ── CVSS metric URIs ──────────────────────────────────────────────────────────
class CVSSVocab:
    CVSS2BaseMetric = CVSS.CVSS2BaseMetric
    CVSS3BaseMetric = CVSS.CVSS3BaseMetric
    baseScore               = CVSS.baseScore
    confidentialityImpact   = CVSS.confidentialityImpact
    integrityImpact         = CVSS.integrityImpact
    availabilityImpact      = CVSS.availabilityImpact
    accessVector            = CVSS.accessVector
    attackComplexity        = CVSS.attackComplexity
    vectorString            = CVSS.vectorString

# ── CWE URIs ──────────────────────────────────────────────────────────────────
class CWEVocab:
    Weakness            = CWE_NS.Weakness
    name                = CWE_NS.name
    status              = CWE_NS.status
    abstraction         = CWE_NS.abstraction
    hasCAPEC            = CWE_NS.hasCAPEC
    hasCommonConsequence = CWE_NS.hasCommonConsequence
    consequenceImpact   = CWE_NS.consequenceImpact
    consequenceScope    = CWE_NS.consequenceScope

# ── CAPEC URIs ────────────────────────────────────────────────────────────────
class CAPECVocab:
    AttackPattern   = CAPEC.AttackPattern
    name            = CAPEC.name
    abstraction     = CAPEC.abstraction
    status          = CAPEC.status
    description     = CAPEC.description
    mitigation      = CAPEC.mitigation
    prerequisite    = CAPEC.prerequisite
    likelihood      = CAPEC.likelihood
    severity        = CAPEC.severity
    hasCWE          = CAPEC.hasCWE
    issued          = CAPEC.issued

# ── CPE URIs ──────────────────────────────────────────────────────────────────
class CPEVocab:
    CPE     = CPE_NS.CPE
    cpeId   = CPE_NS.cpeId
    vendor  = CPE_NS.vendor
    product = CPE_NS.product
    version = CPE_NS.version
    part    = CPE_NS.part

# ── ATT&CK URIs (Kurniawan et al. 2021 extension) ────────────────────────────
class ATTVocab:
    Tactic          = ATT.Tactic
    Technique       = ATT.Technique
    Mitigation      = ATT.Mitigation
    AdversaryGroup  = ATT.AdversaryGroup
    Software        = ATT.Software
    accomplishesTactic   = ATT.accomplishesTactic
    isSubTechnique       = ATT.isSubTechnique
    preventsTechnique    = ATT.preventsTechnique
    usesTechnique        = ATT.usesTechnique
    implementsTechnique  = ATT.implementsTechnique
    hasCAPEC             = ATT.hasCAPEC
    hasMitigation        = ATT.hasMitigation
    hasTechnique         = ATT.hasTechnique

# ── Helper: build a CPE URI the same way the original Java engine does ────────
import re

def cpe_uri(cpe_string: str) -> str:
    """
    Convert a raw CPE string like
      cpe:/o:apple:mac_os_x:10.14.1
    to the SEPSES resource URI
      http://w3id.org/sepses/resource/cpe/cpeoapplemac_os_x10.14.1
    Matches the XPath-based normalization in the original engine.
    """
    # strip scheme
    s = re.sub(r'^cpe:[/a-z]*:', 'cpe', cpe_string)
    # collapse separators
    s = re.sub(r'[:/\-\.\s]', '', s).lower()
    return str(R_CPE) + s

def cve_uri(cve_id: str) -> URIRef:
    return R_CVE[cve_id.upper()]

def cwe_uri(cwe_id: str) -> URIRef:
    """cwe_id like 'CWE-125' or just '125'"""
    cid = cwe_id.upper()
    if not cid.startswith("CWE-"):
        cid = f"CWE-{cid}"
    return R_CWE[cid]

def capec_uri(capec_id: str) -> URIRef:
    cid = str(capec_id).upper()
    if not cid.startswith("CAPEC-"):
        cid = f"CAPEC-{cid}"
    return R_CAPEC[cid]
