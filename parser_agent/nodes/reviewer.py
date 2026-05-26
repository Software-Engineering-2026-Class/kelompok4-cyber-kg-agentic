from ..state import ParserState
from langchain_core.messages import AIMessage

def reviewer(state: ParserState) -> ParserState:
    print("  [REVIEWER] Reviewing parsing process...")
    
    parsed_results = state.get("parsed_results", [])
    
    total = len(parsed_results)
    success = sum(1 for r in parsed_results if r["status"] == "success")
    failed = total - success
    
    summary = f"Parsing complete. {success} out of {total} datasets parsed successfully."
    
    if failed > 0:
        summary += f" Failed: {failed}."
    
    return {
        "all_done": True,
        "messages": [AIMessage(content=summary)]
    }
