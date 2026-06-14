# Changelog
All notable changes to the Cybersecurity Knowledge Graph (CSKG) pipeline project will be documented in this file.

## [1.0.0] - 2026-06-14
### Added
- **Docker Integration**: Added a root `Dockerfile` and `docker-compose.yml` to spin up Virtuoso and build the pipeline.
- **Port Documentation**: Port mappings documented in `docker-compose.yml` comments.
- **Quick Start Documentation**: Included 'Quick Start with Docker' guides in `README.md`.
- **System Architecture Visualizations**: Created Mermaid diagram illustrating the flow between parser, linking, validation agents, and endpoints.
- **Environment Template**: Created `.env.example` containing references to all environment configurations (`GOOGLE_API_KEY`, `NVD_API_KEY`, `VIRTUOSO_HOST`, `VIRTUOSO_CONTAINER`).
- **Use Cases**: Documented three query use-cases in `sparql_endpoint/use_cases/USE_CASES.md`.

### Changed
- **Dependency Management**: Renamed root dependencies file to `requirements.txt` (from `requirement.txt`) and updated references.
- **Container Naming**: Renamed Virtuoso container to `cskg-sparql` to clearly match the service name.

### Fixed
- Fixed hardcoded fallback container name in loader script (`sparql_endpoint/load.py`).
