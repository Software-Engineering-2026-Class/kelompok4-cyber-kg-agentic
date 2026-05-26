from .state import ValidationState
from langgraph.graph import StateGraph, END
from .nodes.planner import planner
from .nodes.executor import executor
from .nodes.reviewer import reviewer


def route_executor(state: ValidationState) -> str:
    """
    Rute kondisional pasca Executor:
    Jika masih ada tugas aktif (current_task), lanjutkan eksekusi di node executor.
    Jika tugas aktif kosong, alihkan ke node reviewer.
    """
    if state.get("current_task"):
        return "executor"
    return "reviewer"


def route_reviewer(state: ValidationState) -> str:
    """
    Rute kondisional pasca Reviewer:
    Jika status all_done bernilai True, akhiri grafik (END).
    Jika all_done bernilai False, alihkan kembali ke executor (fallback safety).
    """
    if state.get("all_done"):
        return END
    return "executor"


# Inisialisasi StateGraph dengan ValidationState
builder = StateGraph(ValidationState)

# Daftarkan simpul-simpul (Nodes)
builder.add_node("planner", planner)
builder.add_node("executor", executor)
builder.add_node("reviewer", reviewer)

# Set alur masuk utama
builder.set_entry_point("planner")
builder.add_edge("planner", "executor")

# Daftarkan jalur transisi kondisional (Conditional Edges)
builder.add_conditional_edges(
    "executor", route_executor,
    {"executor": "executor", "reviewer": "reviewer"}
)
builder.add_conditional_edges(
    "reviewer", route_reviewer,
    {END: END, "executor": "executor"}
)

# Kompilasi grafik menjadi runnable instance
graph = builder.compile()
