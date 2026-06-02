# SPARQL Security Use Cases
**SEPSES Cybersecurity Knowledge Graph — Kelompok 4**

Dokumen ini menjabarkan 3 use case keamanan siber yang diimplementasikan
menggunakan SPARQL pada knowledge graph SEPSES yang telah dikonstruksi.

---

## Use Case 1: Vulnerability Attack Chain Analysis

### Skenario
Seorang SOC analyst mendeteksi aktivitas mencurigakan di jaringan dan
ingin menelusuri rantai serangan lengkap dari suatu CVE — mulai dari
jenis kelemahan software (CWE), pola serangan yang mungkin digunakan
(CAPEC), hingga teknik ATT&CK yang relevan untuk membuat detection rule
di SIEM/EDR.

### SPARQL Query
```sparql
PREFIX cve:   <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe:   <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attck: <http://w3id.org/sepses/vocab/ref/attack#>

SELECT DISTINCT ?cveId ?cweName ?capecId ?attckTechnique
WHERE {
  GRAPH <http://w3id.org/sepses/graph/cve_to_cwe> {
    ?cve cve:hasCWE ?cweNode .
  }
  GRAPH <http://w3id.org/sepses/graph/cve> {
    ?cve cve:id ?cveId .
  }
  GRAPH <http://w3id.org/sepses/graph/cwe> {
    ?cweNode cwe:name ?cweName .
  }
  GRAPH <http://w3id.org/sepses/graph/cwe_to_capec> {
    ?cweNode cwe:hasCAPEC ?capecNode .
  }
  GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
    ?capecNode capec:hasRelatedAttackPattern ?attckNode .
    BIND(STRAFTER(STR(?capecNode), "capec/") AS ?capecId)
    BIND(STRAFTER(STR(?attckNode), "attack/") AS ?attckTechnique)
  }
}
ORDER BY ?cveId
LIMIT 20
```

### Contoh Hasil

| CVE ID | CWE Name | CAPEC | ATT&CK |
|---|---|---|---|
| CVE-1999-0007 | Use of a Broken or Risky Cryptographic Algorithm | CAPEC-473 | T1553.002 |
| CVE-1999-0007 | Use of a Broken or Risky Cryptographic Algorithm | CAPEC-473 | T1036.001 |
| CVE-1999-0012 | Authentication Bypass by Spoofing | CAPEC-60 | T1550.004 |
| CVE-1999-0012 | Authentication Bypass by Spoofing | CAPEC-21 | T1134 |
| CVE-1999-0012 | Authentication Bypass by Spoofing | CAPEC-94 | T1557 |

### Relevansi Keamanan
Query ini menelusuri rantai serangan multi-layer **CVE → CWE → CAPEC → ATT&CK**.
Nilai praktisnya:
- **SOC/DFIR**: Analyst dapat memahami *bagaimana* suatu CVE dieksploitasi
  dalam konteks teknik serangan nyata, bukan hanya *bahwa* CVE itu berbahaya.
- **Detection Engineering**: Hasil ATT&CK technique ID dapat langsung
  digunakan untuk mencari atau membuat detection rule di SIEM (Sigma rules,
  Splunk queries, dll).
- **Threat Intelligence**: Menghubungkan vulnerability database (NVD) dengan
  threat framework (ATT&CK) dalam satu query — sesuatu yang tidak bisa
  dilakukan dengan tool konvensional tanpa knowledge graph.

---

## Use Case 2: Exploited Vulnerability Prioritization

### Skenario
Tim vulnerability management menghadapi ratusan CVE setiap bulan dan
perlu memprioritaskan patch. Dengan menggabungkan data CISA Known
Exploited Vulnerabilities (KEV) dengan informasi vendor dan produk
terdampak, tim dapat fokus pada CVE yang **sudah terbukti dieksploitasi
di lapangan** — bukan hanya berdasarkan CVSS score teoritis.

### SPARQL Query
```sparql
PREFIX cve:  <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX icsa: <http://w3id.org/sepses/vocab/ref/icsa#>
PREFIX cwe:  <http://w3id.org/sepses/vocab/ref/cwe#>

SELECT DISTINCT ?cveId ?vendor ?product
(COUNT(DISTINCT ?icsaNode) AS ?exploitCount)
WHERE {
  GRAPH <http://w3id.org/sepses/graph/icsa> {
    ?icsaNode a icsa:ICSA ;
              icsa:cveID ?cveId ;
              icsa:vendorProject ?vendor ;
              icsa:product ?product .
  }
}
GROUP BY ?cveId ?vendor ?product
ORDER BY DESC(?exploitCount) ?vendor
LIMIT 20
```

### Contoh Hasil

| CVE ID | Vendor | Product | Exploit Count |
|---|---|---|---|
| CVE-2025-0411 | 7-Zip | 7-Zip | 1 |
| CVE-2024-54085 | AMI | MegaRAC SPx | 1 |
| CVE-2025-59374 | ASUS | Live Update | 1 |
| CVE-2021-32030 | ASUS | Routers | 1 |
| CVE-2021-27103 | Accellion | FTA | 1 |
| CVE-2021-44207 | Acclaim Systems | USAHERDS | 1 |

### Relevansi Keamanan
CISA KEV (Known Exploited Vulnerabilities) adalah daftar CVE yang
**sudah terbukti dieksploitasi secara aktif** oleh threat actors nyata.
Nilai praktisnya:
- **Patch Management**: Organisasi dapat menggunakan hasil ini sebagai
  *mandatory patch list* — CISA mewajibkan agensi federal AS untuk
  menambal CVE di daftar KEV dalam tenggat waktu tertentu.
- **Asset Inventory**: Dengan mencocokkan vendor/produk dari hasil query
  dengan asset inventory internal, tim keamanan dapat mengidentifikasi
  sistem yang berisiko tinggi secara langsung.
- **Risk Prioritization**: Berbeda dari CVSS score yang bersifat teoritis,
  KEV membership adalah bukti nyata bahwa kerentanan sedang dieksploitasi —
  ini adalah signal terpenting untuk prioritisasi.

---

## Use Case 3: ATT&CK Technique Coverage Mapping

### Skenario
Tim red team ingin merencanakan adversary emulation exercise dan perlu
mengetahui teknik ATT&CK mana yang memiliki paling banyak variasi
eksekusi (berdasarkan mapping ke CAPEC). Teknik dengan banyak CAPEC
mapping berarti ada banyak cara berbeda untuk mengeksekusinya —
lebih sulit dideteksi dan lebih penting untuk diuji.

### SPARQL Query
```sparql
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attck: <http://w3id.org/sepses/vocab/ref/attack#>

SELECT ?techniqueId ?techniqueName ?techniqueDesc
       (COUNT(DISTINCT ?capecNode) AS ?capecCount)
WHERE {
  GRAPH <http://w3id.org/sepses/graph/capec_to_attck> {
    ?capecNode capec:hasRelatedAttackPattern ?attckNode .
  }
  GRAPH <http://w3id.org/sepses/graph/attck_enterprise> {
    ?attckNode attck:techniqueId ?techniqueId .
    ?attckNode attck:name ?techniqueName .
    OPTIONAL { ?attckNode attck:description ?techniqueDesc . }
  }
}
GROUP BY ?techniqueId ?techniqueName ?techniqueDesc
ORDER BY DESC(?capecCount)
LIMIT 15
```

### Contoh Hasil

| Technique ID | Technique Name | CAPEC Count |
|---|---|---|
| T1195.003 | Compromise Hardware Supply Chain | 12 |
| T1195.002 | Compromise Software Supply Chain | 8 |
| T1195.001 | Compromise Software Dependencies | 7 |
| T1499.002 | Service Exhaustion Flood | 5 |
| T1552.004 | Private Keys | 4 |
| T1548 | Abuse Elevation Control Mechanism | 4 |
| T1574.010 | Services File Permissions Weakness | 3 |

### Relevansi Keamanan
Jumlah CAPEC mapping per teknik ATT&CK mengindikasikan **kompleksitas
dan variabilitas** cara eksekusi suatu teknik. Nilai praktisnya:
- **Red Team Planning**: Teknik dengan CAPEC count tinggi (T1195.003 = 12)
  harus menjadi prioritas dalam adversary emulation — banyak variasi
  eksekusi berarti coverage deteksi yang ada mungkin tidak mencakup
  semua cara teknik itu dilakukan.
- **Blue Team Detection Gap Analysis**: Supply Chain Compromise (T1195)
  mendominasi top 3 — ini mengindikasikan bahwa KG mencerminkan tren
  ancaman nyata (SolarWinds, XZ Utils, dll) dan blue team harus
  memastikan deteksi yang memadai.
- **Purple Team Exercises**: Hasil ini dapat langsung dijadikan agenda
  purple team: simulasikan T1195.003 dengan berbagai CAPEC pattern,
  ukur berapa persen yang terdeteksi oleh blue team.

---

## Ringkasan Use Cases

| # | Use Case | Graph Yang Digunakan | Hasil |
|---|---|---|---|
| 1 | Attack Chain Analysis | cve, cve_to_cwe, cwe, cwe_to_capec, capec_to_attck, attck_enterprise | 20 attack chains |
| 2 | Exploited Vuln Prioritization | icsa, icsa_to_cve | 1,608 KEV entries |
| 3 | ATT&CK Coverage Mapping | capec_to_attck, attck_enterprise | 15 top techniques |

Ketiga use case ini mendemonstrasikan nilai praktis knowledge graph
dalam konteks keamanan siber — menghubungkan data dari sumber yang
berbeda (NVD, MITRE, CISA) dalam satu query yang tidak mungkin
dilakukan dengan database relasional konvensional.