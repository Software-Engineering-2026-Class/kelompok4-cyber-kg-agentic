import re

# =====================================================================
# NAMESPACES & RESOURCE BASES
# =====================================================================
# Menyamakan namespace dengan yang digunakan di linking_agent dan parser_agent
NAMESPACES = {
    "cve":   "http://w3id.org/sepses/vocab/ref/cve#",
    "cwe":   "http://w3id.org/sepses/vocab/ref/cwe#",
    "capec": "http://w3id.org/sepses/vocab/ref/capec#",
    "cpe":   "http://w3id.org/sepses/vocab/ref/cpe#",
    "cvss":  "http://w3id.org/sepses/vocab/ref/cvss#",
    "attck": "http://w3id.org/sepses/vocab/ref/attack#",
    "icsa":  "http://w3id.org/sepses/vocab/ref/icsa#",
    "rdf":   "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs":  "http://www.w3.org/2000/01/rdf-schema#",
    "xsd":   "http://www.w3.org/2001/XMLSchema#",
}

# =====================================================================
# MATRIKS ATURAN VALIDASI (VALIDATION CONSTRAINT MATRIX)
# =====================================================================
# Berisi spesifikasi properti wajib, tipe, ekspresi reguler (regex),
# dan tingkat keparahan pelanggaran (Severity: ERROR atau WARNING)
VALIDATION_RULES = {
    "http://w3id.org/sepses/vocab/ref/cve#CVE": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/cve#id": {
                "type": "literal",
                "regex": r"^CVE-\d{4}-\d{4,}$",
                "severity": "ERROR",
                "description": "Identifier CVE harus valid sesuai format standar NVD (CVE-YYYY-NNNN+)"
            },
            "http://w3id.org/sepses/vocab/ref/cve#description": {
                "type": "literal",
                "severity": "WARNING",
                "description": "Deskripsi rinci dari kerentanan keamanan siber"
            }
        },
        "links": {
            "http://w3id.org/sepses/vocab/ref/cve#hasCWE": {
                "target_class": "http://w3id.org/sepses/vocab/ref/cwe#CWE",
                "severity": "WARNING",
                "description": "Relasi dari kerentanan CVE ke kelemahan CWE terkait"
            },
            "http://w3id.org/sepses/vocab/ref/cve#hasCPE": {
                "target_class": "http://w3id.org/sepses/vocab/ref/cpe#CPE",
                "severity": "WARNING",
                "description": "Relasi dari kerentanan CVE ke produk terdampak CPE terkait"
            }
        }
    },
    "http://w3id.org/sepses/vocab/ref/cwe#CWE": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/cwe#id": {
                "type": "literal",
                "regex": r"^CWE-\d+$",
                "severity": "ERROR",
                "description": "Identifier CWE harus valid sesuai format standar MITRE (CWE-ID)"
            },
            "http://w3id.org/sepses/vocab/ref/cwe#name": {
                "type": "literal",
                "severity": "ERROR",
                "description": "Nama resmi dari kelemahan perangkat lunak"
            },
            "http://w3id.org/sepses/vocab/ref/cwe#description": {
                "type": "literal",
                "severity": "WARNING",
                "description": "Deskripsi teknis mengenai kelemahan terkait"
            }
        },
        "links": {
            "http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC": {
                "target_class": "http://w3id.org/sepses/vocab/ref/capec#CAPEC",
                "severity": "WARNING",
                "description": "Relasi dari kelemahan CWE ke pola serangan CAPEC terkait"
            }
        }
    },
    "http://w3id.org/sepses/vocab/ref/capec#CAPEC": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/capec#id": {
                "type": "literal",
                "regex": r"^CAPEC-\d+$",
                "severity": "ERROR",
                "description": "Identifier CAPEC harus valid sesuai format standar MITRE (CAPEC-ID)"
            },
            "http://w3id.org/sepses/vocab/ref/capec#name": {
                "type": "literal",
                "severity": "ERROR",
                "description": "Nama resmi dari pola serangan terkait"
            },
            "http://w3id.org/sepses/vocab/ref/capec#description": {
                "type": "literal",
                "severity": "WARNING",
                "description": "Deskripsi teknis mengenai jalannya pola serangan"
            }
        },
        "links": {
            "http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern": {
                "target_class": "http://w3id.org/sepses/vocab/ref/attack#AttackPattern",
                "severity": "WARNING",
                "description": "Relasi dari pola serangan CAPEC ke teknik MITRE ATT&CK terkait"
            }
        }
    },
    "http://w3id.org/sepses/vocab/ref/cpe#CPE": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/cpe#id": {
                "type": "literal",
                "severity": "ERROR",
                "description": "CPE Name Identifier unik"
            },
            "http://w3id.org/sepses/vocab/ref/cpe#cpe23Uri": {
                "type": "literal",
                "severity": "ERROR",
                "description": "URI CPE v2.3 formal untuk identifikasi perangkat keras/lunak"
            }
        }
    },
    "http://w3id.org/sepses/vocab/ref/icsa#ICSA": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/icsa#cveID": {
                "type": "literal",
                "regex": r"^CVE-\d{4}-\d{4,}$",
                "severity": "ERROR",
                "description": "CVE ID yang dirujuk oleh advisory industri ICSA"
            },
            "http://w3id.org/sepses/vocab/ref/icsa#vendorProject": {
                "type": "literal",
                "severity": "ERROR",
                "description": "Nama vendor/pabrikan sistem industri terdampak"
            },
            "http://w3id.org/sepses/vocab/ref/icsa#product": {
                "type": "literal",
                "severity": "ERROR",
                "description": "Nama produk industri terdampak"
            }
        },
        "links": {
            "http://w3id.org/sepses/vocab/ref/icsa#hasCVE": {
                "target_class": "http://w3id.org/sepses/vocab/ref/cve#CVE",
                "severity": "WARNING",
                "description": "Hubungan formal dari penasehat industri ICSA ke entitas kerentanan CVE"
            }
        }
    },
    "http://w3id.org/sepses/vocab/ref/attack#AttackPattern": {
        "mandatory_properties": {
            "http://w3id.org/sepses/vocab/ref/attack#id": {
                "type": "literal",
                "severity": "ERROR",
                "description": "ID teknis otonom dari objek pola serangan STIX ATT&CK"
            },
            "http://w3id.org/sepses/vocab/ref/attack#name": {
                "type": "literal",
                "severity": "ERROR",
                "description": "Nama teknik serangan ATT&CK terkait"
            },
            "http://w3id.org/sepses/vocab/ref/attack#techniqueId": {
                "type": "literal",
                "regex": r"^T\d{4}(?:\.\d{3})?$",
                "severity": "ERROR",
                "description": "Identifier resmi MITRE ATT&CK (contoh: T1059 atau T1059.001)"
            }
        }
    }
}
