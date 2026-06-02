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