# Cybersecurity Knowledge Graph (CSKG) Pipeline

This project implements a multi-agent pipeline to fetch, parse, link, validate, and query cybersecurity data (CVE, CWE, CAPEC, ATT&CK) using the SEPSES ontology.

## Installation

### Prerequisites

- Python 3.8+
- Docker & Docker Compose (for the SPARQL Endpoint)
- `pip` or `pipenv`

### Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Software-Engineering-2026-Class/kelompok4-cyber-kg-agentic
   cd cskg
   ```

2. **Install dependencies:**
   Each agent has its own virtual environment setup. You can either install dependencies globally or per agent.
   A root `requirement.txt` exists. You can install via:
   ```bash
   pip install -r requirement.txt
   ```

## Configuration

Configuration is primarily handled through environment variables and agent-specific `.env` or `config.py` files.

1. **Environment Variables:**
   Rename `.env.example` to `.env` (if applicable) or create a `.env` file in the root and agent directories (like `fetcher_agent/.env`) to store API keys or configurations.
2. **Virtuoso Configuration:**
   The SPARQL endpoint is configured via `sparql_endpoint/docker-compose.yaml`. The default exposed ports are `8890` (HTTP/SPARQL) and `1111` (ISQL).

## How to Run the Pipeline

The pipeline is modular and should be run sequentially to ensure data flows correctly from fetching to the SPARQL endpoint.

### 1. Fetcher Agent

Fetches cybersecurity datasets.

```bash
python fetcher_agent/main.py
```

_Wait for the fetch process to complete. Data is typically stored in a cache or output directory._

### 2. Parser Agent

Parses the fetched datasets and maps them to the SEPSES ontology classes.

```bash
python parser_agent/main.py
```

### 3. Linking Agent

Identifies and builds relationships between sources (e.g., CVE→CWE→CAPEC→ATT&CK).

```bash
python linking_agent/main.py
```

### 4. Validation Agent

Validates the semantic quality and structure of the generated Turtle (`.ttl`) files.

```bash
python validation_agent/main.py
```

### 5. SPARQL Endpoint

Loads the validated TTL files into an OpenLink Virtuoso instance.

**Start the Database:**

```bash
cd sparql_endpoint
docker-compose up -d
```

**Load the Data:**
Make sure the output `.ttl` files from the pipeline are in the `toload` directory.

```bash
python load.py
```

**Verify the Endpoint:**

```bash
python verify.py
```

## Expected Outputs

- **Fetcher Agent:** Raw cybersecurity data files (JSON, XML, CSV, etc.) stored in `fetcher_agent/cache/`.
- **Parser Agent:** Intermediate parsed Turtle (`.ttl`) files mapped to SEPSES ontology.
- **Linking Agent:** Linked Turtle files containing relationship triples, saved in `linking_agent/output/`.
- **Validation Agent:** Validation reports summarizing triple counts, subjects, errors, and warnings.
- **SPARQL Endpoint:** A fully queryable Knowledge Graph at `http://localhost:8890/sparql` with named graphs such as `http://w3id.org/sepses/graph/cve` and links like `http://w3id.org/sepses/graph/cve_to_cwe`.

## Known Limitations

- **Performance Constraints:** Loading very large datasets (like the full NVD dataset) into Virtuoso locally may consume significant RAM and take a long time.
- **Missing Triples:** The validation agent might flag missing mandatory triples if the upstream data source (e.g., MITRE or NVD) has incomplete entries.
- **Sequential Dependency:** The pipeline currently requires manual sequential execution. If `fetcher_agent` fails or updates partial data, downstream agents must be re-run manually.
- **Stale Data:** Fetched data is cached; you must clear the cache or adjust fetch instructions to pull the latest upstream vulnerability advisories.
- **Limited CVE & CPE Data (Demo Mode):** The CVE and CPE fetchers are currently capped at 100 records for development purposes. This causes a high error rate in `icsa_to_cve.ttl` and `cve_to_cpe.ttl` because most CVEs referenced by the ICSA are missing from the base dataset. 
  * **Fix:** Remove `MAX_DEMO = 100` in `fetcher_agent/fetchers/nvd.py` and use an NVD API key to perform a full fetch (~350K CVEs, estimated to take 2–4 hours).

## 10. Contributor

| Name | GitHub | Role |
|---|---|---|
| Atha Putra Fausta | [@ahtape](https://github.com/ahtape) | Validation Agent & Evaluation |
| Fikar Adi Nugraha | [@Gatoetkatja](https://github.com/Gatoetkatja) | Fetcher Agent & SPARQL Endpoint |
| Abdul Hamid Awaludin Ardiansyah | [@asistink](https://github.com/asistink) | Linking Agent & Evaluation |
| Khoirul Adib Fairuza | [@feinru](https://github.com/feinru) | Parser Agent & SPARQL Endpoint |

---
