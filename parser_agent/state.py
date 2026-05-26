from typing import Optional, Any
from langgraph.graph import MessagesState

class ParserState(MessagesState):
    parse_plan: list[dict]
    current_task: dict
    parsed_results: list[dict]
    all_done: bool
