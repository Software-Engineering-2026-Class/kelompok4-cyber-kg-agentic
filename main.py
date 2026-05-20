"""
main.py  —  Run the Cyber-KG agentic pipeline.

Usage:
  python main.py                  # full pipeline
  python main.py --dry-run        # show tool schemas, no API calls
  python main.py --goal "..."     # custom goal
"""

import argparse
import json
import logging
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="SEPSES Cyber-KG Agentic Pipeline")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print tool schemas and exit without calling API")
    parser.add_argument("--goal",    type=str, default=None,
                        help="Override the default pipeline goal")
    parser.add_argument("--verbose", action="store_true",
                        help="DEBUG-level logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(name)-12s  %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("output/agent.log", mode="w"),
        ],
    )

    Path("output").mkdir(exist_ok=True)

    if args.dry_run:
        from tools.tools import get_tool_schemas
        schemas = get_tool_schemas()
        print(f"\nRegistered tools ({len(schemas)}):\n")
        for s in schemas:
            print(f"  ► {s['name']}")
            print(f"    {s['description'][:80]}")
            print()
        sys.exit(0)

    from agent import CyberKGAgent
    agent = CyberKGAgent()
    summary = agent.run(goal=args.goal)
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print(summary)

if __name__ == "__main__":
    main()
