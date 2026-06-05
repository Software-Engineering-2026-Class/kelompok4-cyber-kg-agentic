import os
import requests
import json
import warnings

try:
    from langgraph.warnings import LangGraphDeprecatedSinceV10

    warnings.filterwarnings("ignore", category=LangGraphDeprecatedSinceV10)
except ImportError:
    pass
from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent

# Load environment variables (make sure GOOGLE_API_KEY is in .env)
load_dotenv()

SPARQL_ENDPOINT = "http://localhost:8890/sparql"


@tool
def execute_sparql_query(query: str) -> str:
    """
    Execute a SPARQL query against the Cybersecurity Knowledge Graph (CSKG)
    and return the results as a JSON string. Use this to fetch data to answer the user's question.
    """
    try:
        resp = requests.get(
            SPARQL_ENDPOINT,
            params={"query": query, "format": "application/sparql-results+json"},
            timeout=30,
        )
        resp.raise_for_status()

        # Parse the standard SPARQL JSON response format
        bindings = resp.json().get("results", {}).get("bindings", [])

        # Clean up bindings to a simpler JSON list of dicts for the LLM to read easily
        cleaned_results = []
        for row in bindings:
            cleaned_row = {k: v["value"] for k, v in row.items()}
            cleaned_results.append(cleaned_row)

        return json.dumps(cleaned_results, indent=2)
    except Exception as e:
        return f"Error executing SPARQL query: {str(e)}"


# Define the Ontology / System Prompt for the LLM
SYSTEM_PROMPT = """You are a Senior SOC Analyst and Knowledge Graph Expert.
Your job is to answer security questions by querying a Cybersecurity Knowledge Graph (CSKG) via SPARQL.

You have access to the `execute_sparql_query` tool. 
ALWAYS write and execute a SPARQL query before answering.

Here is the ontology schema you MUST use for your SPARQL queries:
- Prefixes:
  PREFIX cve:   <http://w3id.org/sepses/vocab/ref/cve#>
  PREFIX cwe:   <http://w3id.org/sepses/vocab/ref/cwe#>
  PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
  PREFIX attck: <http://w3id.org/sepses/vocab/ref/attack#>
  PREFIX icsa:  <http://w3id.org/sepses/vocab/ref/icsa#>

- Available Graphs and Relations:
  1. GRAPH <http://w3id.org/sepses/graph/cve>
     - ?cve cve:id ?cveId .
  2. GRAPH <http://w3id.org/sepses/graph/cve_to_cwe>
     - ?cve cve:hasCWE ?cweNode .
  3. GRAPH <http://w3id.org/sepses/graph/cwe>
     - ?cweNode cwe:name ?cweName .
  4. GRAPH <http://w3id.org/sepses/graph/cwe_to_capec>
     - ?cweNode cwe:hasCAPEC ?capecNode .
  5. GRAPH <http://w3id.org/sepses/graph/capec_to_attck>
     - ?capecNode capec:hasRelatedAttackPattern ?attckNode .
  6. GRAPH <http://w3id.org/sepses/graph/attck_enterprise>
     - ?attckNode attck:techniqueId ?techniqueId .
     - ?attckNode attck:name ?techniqueName .
     - ?attckNode attck:description ?techniqueDesc .
  7. GRAPH <http://w3id.org/sepses/graph/icsa> (CISA Known Exploited Vulnerabilities)
     - ?icsaNode a icsa:ICSA .
     - ?icsaNode icsa:cveID ?cveId .
     - ?icsaNode icsa:vendorProject ?vendor .
     - ?icsaNode icsa:product ?product .

When the user asks a question:
1. Write the appropriate SPARQL query string based on the user's intent.
2. Show the SPARQL query you will execute.
3. Use the `execute_sparql_query` tool to execute it.
4. Read the JSON results.
5. Provide a clear, detailed security explanation based on the returned data. Explain *why* the findings matter from a threat intelligence or SOC perspective (just like a real analyst would).
"""


def create_query_agent():
    # Make sure GOOGLE_API_KEY is set in the environment or .env
    # We use gemini-2.5-flash to match the rest of your agents
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
    tools = [execute_sparql_query]

    agent = create_react_agent(model=llm, tools=tools, prompt=SYSTEM_PROMPT)
    return agent


def main():
    # Check for API key
    if not os.environ.get("GOOGLE_API_KEY"):
        print(
            "Error: GOOGLE_API_KEY is not set. Please set it in your .env file or export it in your terminal."
        )
        return

    print("=" * 70)
    print("  CSKG NL2SPARQL SOC Analyst Agent")
    print("  Type 'quit' or 'exit' to stop.")
    print("=" * 70)

    agent = create_query_agent()

    while True:
        try:
            user_input = input("\n[Analyst]: ")
        except (KeyboardInterrupt, EOFError):
            break

        if user_input.lower() in ["quit", "exit"]:
            break

        if not user_input.strip():
            continue

        print("\n[Agent is thinking & querying Virtuoso...]")

        try:
            # Stream the agent's execution
            events = agent.stream(
                {"messages": [("user", user_input)]}, stream_mode="values"
            )

            # langgraph's stream_mode="values" yields the full state at each step.
            # We capture the final message from the agent.
            last_message = None
            for event in events:
                last_message = event["messages"][-1]

            if last_message and hasattr(last_message, "content"):
                print("\n[Agent]:")
                content = last_message.content
                if isinstance(content, list):
                    # Gemini sometimes returns a list of content blocks
                    for block in content:
                        if isinstance(block, dict) and "text" in block:
                            print(block["text"])
                        elif isinstance(block, str):
                            print(block)
                else:
                    print(content)
        except Exception as e:
            print(f"\n[Agent Error]: {str(e)}")


if __name__ == "__main__":
    main()
