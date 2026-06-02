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
