# SPARQL Endpoint — SEPSES Cyber-KG

Endpoint SPARQL untuk SEPSES Cybersecurity Knowledge Graph berbasis **OpenLink Virtuoso 7**.

---

## Cara Menjalankan

### Prasyarat
- Docker & Docker Compose
- File TTL hasil pipeline (dari `linking_agent/output/` dan `parser_agent/output/`)

### 1. Jalankan Virtuoso
```bash
cd sparql_endpoint/
docker-compose up -d
```

### 2. Load Data
```bash
python load.py
```

### 3. Verifikasi Endpoint
```bash
python verify.py
```

---

## Endpoint URL

| Layanan | URL |
|---|---|
| SPARQL Endpoint | `http://localhost:8890/sparql` |
| Web UI (Conductor) | `http://localhost:8890/conductor` |
| ISQL Port | `localhost:1111` |

---

## Named Graphs

| Graph URI | Isi |
|---|---|
| `http://w3id.org/sepses/graph/cve` | CVE vulnerabilities |
| `http://w3id.org/sepses/graph/cwe` | CWE weaknesses |
| `http://w3id.org/sepses/graph/cpe` | CPE products |
| `http://w3id.org/sepses/graph/capec` | CAPEC attack patterns |
| `http://w3id.org/sepses/graph/attck_enterprise` | MITRE ATT&CK Enterprise |
| `http://w3id.org/sepses/graph/attck_ics` | MITRE ATT&CK ICS |
| `http://w3id.org/sepses/graph/icsa` | ICSA advisories |
| `http://w3id.org/sepses/graph/cve_to_cwe` | CVE → CWE links |
| `http://w3id.org/sepses/graph/cve_to_cpe` | CVE → CPE links |
| `http://w3id.org/sepses/graph/cwe_to_capec` | CWE → CAPEC links |
| `http://w3id.org/sepses/graph/capec_to_attck` | CAPEC → ATT&CK links |
| `http://w3id.org/sepses/graph/icsa_to_cve` | ICSA → CVE links |

---

## Contoh SPARQL Query

### Hitung total triple
```sparql
SELECT (COUNT(*) AS ?total) WHERE { ?s ?p ?o }
```

### Daftar semua CVE
```sparql
SELECT ?cve ?id WHERE {
  GRAPH <http://w3id.org/sepses/graph/cve> {
    ?cve a <http://w3id.org/sepses/vocab/ref/cve#CVE> ;
         <http://w3id.org/sepses/vocab/ref/cve#id> ?id .
  }
}
```

### Cari teknik ATT&CK terkait suatu CAPEC
```sparql
SELECT ?capec ?attck WHERE {
  GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
    ?capec <http://w3id.org/sepses/vocab/ref/capec#hasRelatedAttackPattern> ?attck .
  }
}
LIMIT 10
```

### Cari CVE terkait suatu advisory ICSA
```sparql
SELECT ?icsa ?cve WHERE {
  GRAPH <http://w3id.org/sepses/graph/icsa_to_cve> {
    ?icsa <http://w3id.org/sepses/vocab/ref/icsa#hasCVE> ?cve .
  }
}
LIMIT 10
```

---

## Struktur Folder

```
sparql_endpoint/
├── docker-compose.yml   # Konfigurasi Virtuoso
├── load.py              # Script loading TTL ke endpoint
├── verify.py            # Script verifikasi basic SPARQL queries
├── toload/              # TTL files yang akan dimuat
└── data/                # Virtuoso database files (auto-generated)
```