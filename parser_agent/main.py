import sys
import os
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    # Add parent directory of parser_agent to sys.path to enable proper package imports
    current_file_path = Path(__file__).resolve()
    parent_dir = current_file_path.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))
    
    # If run from within parser_agent directory, change working directory to project root
    if Path.cwd().name == "parser_agent":
        os.chdir(parent_dir)
        
    from parser_agent.graph import graph
else:
    from .graph import graph

def run_parser_agent():
    print("=" * 50)
    print("  PARSER AGENT — Cybersecurity KG Pipeline")
    print("=" * 50)

    instruction = "Parse all fetched datasets in the cache directory and map them to SEPSES ontology classes."
    print(f"\nInstruction: {instruction}\n")

    result = graph.invoke({
        "messages":       [{"role": "user", "content": instruction}],
        "parse_plan":     [],
        "current_task":   {},
        "parsed_results": [],
        "all_done":       False,
    })

    print("\n" + "=" * 50)
    print("  FINAL RESULTS")
    print("=" * 50)

    success = [r for r in result["parsed_results"] if r.get("status") == "success"]
    failed  = [r for r in result["parsed_results"] if r.get("status") == "failed"]

    for r in result["parsed_results"]:
        icon = "✓" if r.get("status") == "success" else "✗"
        print(f"\n{icon} {r['source'].upper()}")
        print(f"   Status     : {r['status']}")
        print(f"   Entities   : {r.get('entities_count', 0)}")
        if r.get('output_file'):
            print(f"   Output     : {r['output_file']}")
        if r.get("error"):
            print(f"   Error      : {r['error']}")

    print(f"\n{'─'*50}")
    print(f"Success : {len(success)} sources")
    print(f"Failed  : {len(failed)} sources")
    
    if result.get('messages'):
        print(f"\nSummary: {result['messages'][-1].content}")

if __name__ == "__main__":
    run_parser_agent()
