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
   A root `requirements.txt` exists. You can install via:
   ```bash
   pip install -r requirements.txt
   ```

## System Architecture

Below is the conceptual overview of the CSKG agentic pipeline architecture:

```mermaid
graph TD
    A[Fetcher Agent] -->|Raw Data cache/| B[Parser Agent]
    B -->|Base Triples .ttl| C[Linking Agent]
    C -->|Linked Triples .ttl| D[Validation Agent]
    D -->|Quality Check & Report| E[SPARQL Endpoint - Virtuoso]
    E -->|Knowledge Graph| F[NL2SPARQL SOC Analyst Agent]

    subgraph Data Sources
        DS1[CVE - NVD]
        DS2[CPE - NVD]
        DS3[CWE - MITRE]
        DS4[CAPEC - MITRE]
        DS5[ATT&CK - MITRE]
        DS6[ICSA KEV - CISA]
    end

    Data Sources --> A
```

## Configuration

Configuration is primarily handled through environment variables and agent-specific `.env` files.

### Environment Variables

| Variable | Description | Required / Optional | Default Value |
| --- | --- | --- | --- |
| `GOOGLE_API_KEY` | Gemini model access for the query/validation agents. | **Required** | None |
| `NVD_API_KEY` | Optional key to bypass NVD rate limits (fetches faster). | Optional | None |
| `VIRTUOSO_HOST` | Host address of the Virtuoso SPARQL endpoint. | Optional | `localhost` (or `virtuoso` in Compose) |
| `VIRTUOSO_CONTAINER`| Name of the running Virtuoso Docker container. | Optional | `cskg-sparql` |

Rename `.env.example` to `.env` in the project root:
```bash
cp .env.example .env
```

---

## Quick Start with Docker

The easiest way to build, run, and query the entire CSKG pipeline is using Docker Compose.

### 1. Build and Start Services
This starts Virtuoso, builds the pipeline container, and automatically runs the sequential fetch-parse-link-validate-load cycle:
```bash
docker compose up --build
```

### 2. Verify SPARQL Endpoint & Query
Once the pipeline container output shows completion (keeps alive with `tail -f`), verify the endpoint:
- **SPARQL Endpoint**: `http://localhost:8890/sparql`
- **Web Admin UI**: `http://localhost:8890/conductor`

---

## How to Run the Pipeline (Local/Manual)

The pipeline is modular and can also be run sequentially on your host machine.

### 1. Fetcher Agent
Fetches raw datasets:
```bash
python fetcher_agent/main.py
```

### 2. Parser Agent
Parses raw files and maps to SEPSES classes:
```bash
python parser_agent/main.py
```

### 3. Linking Agent
Identifies and maps relationships:
```bash
python linking_agent/main.py
```

### 4. Validation Agent
Validates semantic compliance and structure:
```bash
python validation_agent/main.py
```

### 5. SPARQL Endpoint
Start Virtuoso Database:
```bash
cd sparql_endpoint
docker compose up -d
```
Load the validated TTL files:
```bash
python load.py
```
Verify the endpoint:
```bash
python verify.py
```

---

## Expected Outputs

- **Fetcher Agent:** Raw cybersecurity data files stored in `fetcher_agent/cache/`.
- **Parser Agent:** Parsed Turtle (`.ttl`) files mapped to SEPSES ontology.
- **Linking Agent:** Linked Turtle files containing relationship triples, saved in `linking_agent/output/`.
- **Validation Agent:** Validation reports summarizing triple counts, subjects, errors, and warnings.
- **SPARQL Endpoint:** A fully queryable Knowledge Graph at `http://localhost:8890/sparql` with named graphs such as `http://w3id.org/sepses/graph/cve`.

---

## Security Use Cases
We have documented 3 primary security query use cases in the [USE_CASES.md](file:///mnt/shared/Kuliah/S1/UGM/4/MRPL/tugas_3/cskg/sparql_endpoint/use_cases/USE_CASES.md) file, showing exact query inputs and outputs:
1. **Vulnerability Attack Chain Analysis** (`CVE` -> `CWE` -> `CAPEC` -> `ATT&CK`)
2. **Exploited Vulnerability Prioritization** (`CISA KEV` -> `ICSA` -> `CVE`)
3. **ATT&CK Technique Coverage Mapping** (`CAPEC` -> `ATT&CK`)

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
