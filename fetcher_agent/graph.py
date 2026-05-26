from langgraph.graph import StateGraph, END
from state import FetcherState
from nodes.planner import planner
from nodes.executor import executor
from nodes.reviewer import reviewer

def route_executor(state: FetcherState) -> str:
    """Selama masih ada sumber yang belum diproses, terus loop."""
    if state["current_source"]:
        return "executor"
    return "reviewer"

def route_reviewer(state: FetcherState) -> str:
    if state["all_done"]:
        return END
    return "executor"

builder = StateGraph(FetcherState)

builder.add_node("planner",  planner)
builder.add_node("executor", executor)
builder.add_node("reviewer", reviewer)

builder.set_entry_point("planner")
builder.add_edge("planner", "executor")

builder.add_conditional_edges(
    "executor", route_executor,
    {"executor": "executor", "reviewer": "reviewer"}
)
builder.add_conditional_edges(
    "reviewer", route_reviewer,
    {END: END, "executor": "executor"}
)

graph = builder.compile()
