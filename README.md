# SEPSES-CSKG Agentic Pipeline

An agentic AI-based approach for reproducing and redesigning the SEPSES Cybersecurity Knowledge Graph (CSKG) construction pipeline. This project aims to transform the traditional ETL-based workflow into a dynamic agent-driven pipeline capable of autonomously extracting, parsing, linking, validating, and generating cybersecurity knowledge graphs.

Based on:
- SEPSES-CSKG Paper: https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13
- ICS-Sec KG Paper: https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf
- SEPSES Cyber-KG Converter Repository: https://github.com/sepses/cyber-kg-converter


# Contributors

Atha Putra Fausta - [@ahtape](https://github.com/ahtape)

Fikar Adi Nugraha - [@Gatoetkatja](https://github.com/Gatoetkatja)

Abdul Hamid Awaludin Ardiansyah - [@asistink](https://github.com/asistink)

Khoirul Adib Fairuza - [@feinru](https://github.com/feinru)


# Project Description

Cybersecurity data is distributed across multiple heterogeneous sources such as CVE, CWE, CAPEC, CVSS, MITRE ATT&CK, and ICSA advisories. The original SEPSES-CSKG project integrates these datasets into a unified cybersecurity knowledge graph using a traditional Extract-Transform-Load (ETL) pipeline.

This project explores how recent advances in Agentic AI can be used to redesign the pipeline into a more adaptive and autonomous system. Instead of relying on static scripts and predefined transformations, AI agents will dynamically determine how to process, connect, and validate cybersecurity data during runtime.

The goal is to reproduce the SEPSES-CSKG pipeline while preserving compatibility with the original ontology and RDF schema. The resulting system is expected to maintain or improve the quality of the generated knowledge graph while increasing flexibility, scalability, and automation.

The final output of the project will include:
- An agentic AI pipeline for cybersecurity knowledge graph construction
- RDF/Turtle cybersecurity knowledge graphs
- SPARQL-accessible graph storage
- Knowledge graph statistics and evaluation
- Documentation and open-source implementation


# Objectives

The main objectives of this project are:

1. Study and reproduce the existing SEPSES-CSKG pipeline architecture.
2. Analyze how traditional ETL processes are currently used in cybersecurity knowledge graph construction.
3. Redesign the pipeline using Agentic AI concepts.
4. Develop autonomous agents capable of:
   - Extracting cybersecurity data
   - Parsing heterogeneous formats
   - Linking entities and relationships
   - Validating graph consistency
   - Generating RDF knowledge graphs
5. Maintain compatibility with the ontology and vocabularies used in the original SEPSES-CSKG project.
6. Evaluate the generated knowledge graph using statistical and semantic analysis.
7. Store the resulting RDF graph in a SPARQL endpoint.


# Proposed Concept

## Traditional Pipeline

The original SEPSES-CSKG system uses a conventional ETL workflow:

```text
Extract → Transform → Load
```

Each dataset is processed using predefined scripts and transformation rules before being converted into RDF triples.

---

## Agentic AI Pipeline

This project proposes an agent-based workflow where autonomous AI agents dynamically manage the pipeline process:

```text
Planner Agent
      ↓
Extraction Agents
      ↓
Parsing Agents
      ↓
Entity Linking Agents
      ↓
Validation Agents
      ↓
RDF Generation Agents
      ↓
SPARQL Storage
```

Instead of fixed transformations, agents can:
- Decide how to parse incoming data
- Select tools dynamically
- Resolve entity relationships
- Detect inconsistencies
- Validate RDF structures automatically


# Knowledge Graph Sources

The project focuses on integrating several major cybersecurity datasets:

| Dataset | Description | Source |
|---|---|---|
| CVE | Common Vulnerabilities and Exposures | [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) |
| CVSS | Common Vulnerability Scoring System | [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) |
| CWE | Common Weakness Enumeration | [MITRE CWE](https://cwe.mitre.org/) |
| CPE | Common Platform Enumeration | [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) |
| CAPEC | Common Attack Pattern Enumeration and Classification | [MITRE CAPEC](https://capec.mitre.org/) |
| MITRE ATT&CK Enterprise | Enterprise attack techniques | [MITRE ATT&CK](https://attack.mitre.org/) |
| MITRE ATT&CK ICS | Industrial Control System attack techniques | [MITRE ATT&CK](https://attack.mitre.org/) |
| ICSA | Industrial Control System Advisories | [CISA ICSA](https://www.cisa.gov/news-events/ics-advisories) |


# Data Sources & Access

## NVD Data Feeds

The primary source for CVE, CVSS, and CPE data is the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/vuln/data-feeds). The NVD provides two methods for accessing vulnerability data:

### NVD 2.0 APIs (Preferred)

The [NVD 2.0 APIs](https://nvd.nist.gov/developers) are the recommended method for staying up to date. Key benefits include:
- Real-time updates (synced with the NVD website)
- Advanced search capabilities (by CVE ID, CPE, date range, etc.)
- Ability to retrieve only data changed since a given date/time
- Endpoints:
  - **CVE API**: https://nvd.nist.gov/developers/vulnerabilities
  - **CPE API**: https://nvd.nist.gov/developers/products

> **Note:** An [API key](https://nvd.nist.gov/developers/request-an-api-key) is recommended for higher rate limits.

### NVD JSON 2.0 Data Feeds (Traditional)

For bulk/offline access, the NVD provides downloadable JSON 2.0 feeds:

| Feed | Description | Format |
|---|---|---|
| CVE Vulnerability Feeds | Per-year CVE data (2002–2026), plus `modified` and `recent` feeds | `.json.gz` / `.json.zip` |
| CPE Dictionary Feed | Complete CPE dictionary | `.tar.gz` / `.zip` |
| CPE Match Feed | CPE applicability statements | `.tar.gz` / `.zip` |

- **Schema**: [NVD JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- **Update frequency**: Year feeds updated nightly; `modified` and `recent` feeds updated every 2 hours
- **Sync strategy**: Perform a one-time full import, then use the `modified` feed to stay current
- **META files**: Always check `.meta` files before downloading to determine if a feed has been updated


# References

1. https://link.springer.com/chapter/10.1007/978-3-030-30796-7_13
2. https://eprints.cs.univie.ac.at/8177/1/ISWC24_ICS-SEC__Andreas%20Ekelhart.pdf
3. https://github.com/sepses/cyber-kg-converter
4. https://nvd.nist.gov/vuln/data-feeds
5. https://nvd.nist.gov/developers
