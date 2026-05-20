"""
agent.py  —  The AI agent that plans and executes the KG pipeline.

The agent uses Claude as its reasoning engine.  It receives a high-level
goal ("build a SEPSES-compatible KG from CVE/CWE/CAPEC data"), decides
which tools to call, inspects results, and adapts — exactly like an
agentic loop should.
"""

import json
import logging
import os
import sys
import time
from typing import Any

import anthropic

from tools.tools import get_tool_schemas, call_tool

log = logging.getLogger("agent")

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert cybersecurity knowledge graph (KG) construction agent.

Your mission: build a SEPSES-compatible Cybersecurity Knowledge Graph (CSKG) by:
1. Fetching raw data from public cybersecurity sources (CVE, CWE, CAPEC)
2. Parsing each source into structured records
3. Converting records to RDF using the SEPSES CSKG ontology (w3id.org/sepses/vocab/ref/*)
4. Linking entities across graphs (CVE→CWE→CAPEC) using shared identifiers
5. Validating the generated RDF against SEPSES SHACL-style constraints
6. Merging everything into a final unified KG
7. Running verification SPARQL queries to confirm correctness
8. Reporting final statistics

ONTOLOGY FACTS (strictly follow these):
- CVE URIs:   http://w3id.org/sepses/resource/cve/{CVE-ID}
- CWE URIs:   http://w3id.org/sepses/resource/cwe/{CWE-ID}
- CAPEC URIs: http://w3id.org/sepses/resource/capec/{CAPEC-ID}
- CPE URIs:   http://w3id.org/sepses/resource/cpe/{normalized-id}
- Key links:  cve:hasCWE, cve:hasCPE, cwe:hasCAPEC, capec:hasCWE

SOURCES to use (use these URLs exactly):
- CVE (NVD JSON 1.1):  https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz
  Fallback CVE URL: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip
- CWE:   https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
- CAPEC: https://capec.mitre.org/data/archive/capec_latest.zip

PIPELINE DECISIONS you must make dynamically:
- Decide the order of operations (always do CAPEC and CWE before linking)
- If a fetch fails, try the fallback URL or reduce scope
- If validation finds violations, diagnose and re-convert if fixable
- Use sparql_query after merging to verify cross-source links exist
- Report what you find at each step in your reasoning

Be efficient: parse max_items=200 CVEs to keep runtime reasonable.
Always call report_stats at the end on the merged file.
Think step by step before each tool call. Explain your reasoning briefly.
"""

# ── Verification queries (agent injects these post-merge) ────────────────────
VERIFY_QUERIES = [
    (
        "CVE count",
        """PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
SELECT (COUNT(?x) AS ?n) WHERE { ?x a cve:CVE }"""
    ),
    (
        "CWE count",
        """PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>
SELECT (COUNT(?x) AS ?n) WHERE { ?x a cwe:Weakness }"""
    ),
    (
        "CAPEC count",
        """PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
SELECT (COUNT(?x) AS ?n) WHERE { ?x a capec:AttackPattern }"""
    ),
    (
        "CVE→CWE links",
        """PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
SELECT (COUNT(*) AS ?n) WHERE { ?c cve:hasCWE ?w }"""
    ),
    (
        "CWE→CAPEC links",
        """PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>
SELECT (COUNT(*) AS ?n) WHERE { ?w cwe:hasCAPEC ?a }"""
    ),
    (
        "Sample CVE with CVSS score",
        """PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
SELECT ?cveId ?score WHERE {
  ?c a cve:CVE ; cve:id ?cveId ; cve:hasCVSS2BaseMetric ?m .
  ?m cvss:baseScore ?score .
} LIMIT 5"""
    ),
]


class CyberKGAgent:
    """
    Agentic pipeline that uses Claude to plan + execute KG construction.
    The agent loop:
      1. Send goal + tool schemas to Claude
      2. Claude returns either text (thinking) or tool_use blocks
      3. Execute tool calls, feed results back
      4. Repeat until Claude signals completion
    """

    def __init__(self, model: str = "claude-sonnet-4-20250514", max_turns: int = 40):
        self.client    = anthropic.Anthropic()
        self.model     = model
        self.max_turns = max_turns
        self.tools     = get_tool_schemas()
        self.history: list[dict] = []
        self.turn      = 0

    # ── public entry point ────────────────────────────────────────────────────
    def run(self, goal: str | None = None) -> str:
        if goal is None:
            goal = (
                "Build the SEPSES Cybersecurity Knowledge Graph. "
                "Fetch CVE, CWE, and CAPEC data, convert to RDF using the SEPSES ontology, "
                "link all cross-source references, validate, merge into a final KG, "
                "run verification queries, and report final statistics."
            )

        log.info("=" * 60)
        log.info("CYBER-KG AGENT STARTING")
        log.info(f"Goal: {goal}")
        log.info("=" * 60)

        self.history = [{"role": "user", "content": goal}]

        while self.turn < self.max_turns:
            self.turn += 1
            log.info(f"\n─── Agent turn {self.turn} ───")

            response = self._call_claude()
            stop_reason = response.stop_reason

            # collect assistant content
            assistant_blocks = []
            for block in response.content:
                assistant_blocks.append(block)
                if block.type == "text":
                    log.info(f"[Claude] {block.text[:400]}{'...' if len(block.text) > 400 else ''}")

            self.history.append({"role": "assistant", "content": response.content})

            # finished?
            if stop_reason == "end_turn":
                log.info("Agent finished.")
                final_text = " ".join(b.text for b in response.content if b.type == "text")
                return final_text

            # handle tool calls
            if stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    result = self._execute_tool(block.name, block.input)
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     json.dumps(result, default=str)[:8000],
                    })

                self.history.append({"role": "user", "content": tool_results})
                continue

            # unexpected stop
            log.warning(f"Unexpected stop_reason: {stop_reason}")
            break

        return "Agent reached max turns."

    # ── private helpers ───────────────────────────────────────────────────────
    def _call_claude(self):
        return self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            messages=self.history,
        )

    def _execute_tool(self, name: str, args: dict) -> Any:
        log.info(f"[Tool] {name}({', '.join(f'{k}={repr(v)[:60]}' for k, v in args.items())})")
        try:
            result = call_tool(name, args)
            # summarise large results before logging
            if isinstance(result, list) and len(result) > 3:
                log.info(f"[Tool result] list of {len(result)} items, first: {result[0]}")
            elif isinstance(result, dict):
                log.info(f"[Tool result] {result}")
            else:
                log.info(f"[Tool result] {str(result)[:200]}")
            return result
        except Exception as e:
            log.error(f"[Tool ERROR] {name}: {e}")
            return {"error": str(e), "tool": name}


# ── CLI entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-12s  %(message)s",
        datefmt="%H:%M:%S",
    )

    agent = CyberKGAgent()
    summary = agent.run()
    print("\n" + "=" * 60)
    print("FINAL AGENT SUMMARY")
    print("=" * 60)
    print(summary)
