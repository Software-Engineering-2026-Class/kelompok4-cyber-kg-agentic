from .state import LinkingState
from langgraph.graph import StateGraph, END
from .nodes.planner import planner
from .nodes.executor import executor
from .nodes.reviewer import reviewer


def route_executor(state: LinkingState) -> str:
    if state.get("current_task"):
        return "executor"
    return "reviewer"


def route_reviewer(state: LinkingState) -> str:
    if state.get("all_done"):
        return END
    return "executor"


builder = StateGraph(LinkingState)

builder.add_node("planner", planner)
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
