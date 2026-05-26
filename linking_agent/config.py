NAMESPACES = {
    "cve":   "http://w3id.org/sepses/vocab/ref/cve#",
    "cwe":   "http://w3id.org/sepses/vocab/ref/cwe#",
    "capec": "http://w3id.org/sepses/vocab/ref/capec#",
    "cpe":   "http://w3id.org/sepses/vocab/ref/cpe#",
    "cvss":  "http://w3id.org/sepses/vocab/ref/cvss#",
    "attck": "http://w3id.org/sepses/vocab/ref/attack#",
    "icsa":  "http://w3id.org/sepses/vocab/ref/icsa#",
}

RESOURCE_BASE = {
    "cve":   "http://w3id.org/sepses/resource/cve/",
    "cwe":   "http://w3id.org/sepses/resource/cwe/",
    "capec": "http://w3id.org/sepses/resource/capec/",
    "cpe":   "http://w3id.org/sepses/resource/cpe/",
    "attck": "http://w3id.org/sepses/resource/attack/",
    "icsa":  "http://w3id.org/sepses/resource/icsa/",
}

LINKING_RULES = [
    {
        "link_type":   "cve_to_cwe",
        "subject_src": "cve",
        "object_src":  "cwe",
        "predicate":   "cve:hasCWE",
        "description": "CVE vulnerability linked to CWE weakness",
    },
    {
        "link_type":   "cve_to_cpe",
        "subject_src": "cve",
        "object_src":  "cpe",
        "predicate":   "cve:hasCPE",
        "description": "CVE vulnerability linked to affected CPE product",
    },
    {
        "link_type":   "cwe_to_capec",
        "subject_src": "cwe",
        "object_src":  "capec",
        "predicate":   "cwe:hasCAPEC",
        "description": "CWE weakness linked to CAPEC attack pattern",
    },
    {
        "link_type":   "capec_to_attck",
        "subject_src": "capec",
        "object_src":  "attck",
        "predicate":   "capec:hasRelatedAttackPattern",
        "description": "CAPEC attack pattern linked to MITRE ATT&CK technique",
    },
    {
        "link_type":   "icsa_to_cve",
        "subject_src": "icsa",
        "object_src":  "cve",
        "predicate":   "icsa:hasCVE",
        "description": "ICSA advisory linked to CVE vulnerability",
    },
]
