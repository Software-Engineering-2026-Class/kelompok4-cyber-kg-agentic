from typing import Optional
from langgraph.graph import MessagesState

class SourceResult(dict):
    """Hasil fetch satu sumber."""
    pass

class FetcherState(MessagesState):
    fetch_plan:     list[str]
    current_source: str
    results:        list[dict]
    all_done:       bool
    retry_count:    int