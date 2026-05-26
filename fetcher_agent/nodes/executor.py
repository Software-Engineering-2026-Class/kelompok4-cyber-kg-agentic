from state import FetcherState
from config import FETCHER_REGISTRY

def executor(state: FetcherState) -> FetcherState:
    source = state["current_source"]
    results = list(state["results"])
    plan = state["fetch_plan"]

    print(f"\n[Executor] ── Memproses: {source} ──")

    fetcher_class = FETCHER_REGISTRY.get(source)
    if not fetcher_class:
        result = {
            "source":    source,
            "status":    "failed",
            "records":   0,
            "file_path": "",
            "error":     f"Fetcher untuk '{source}' tidak ditemukan",
        }
    else:
        fetcher = fetcher_class()
        result = fetcher.run()

    # Update results
    results = [r for r in results if r["source"] != source]
    results.append(result)

    # Tentukan sumber berikutnya
    done = {r["source"] for r in results if r["status"] in ("success", "cached", "failed")}
    remaining = [s for s in plan if s not in done]
    next_source = remaining[0] if remaining else ""

    if next_source:
        print(f"\n[Executor] Berikutnya: {next_source}")
    else:
        print(f"\n[Executor] Semua sumber selesai diproses.")

    return {**state, "results": results, "current_source": next_source}
