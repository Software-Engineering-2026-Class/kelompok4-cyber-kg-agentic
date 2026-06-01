from ..state import LinkingState
from langchain_core.messages import AIMessage


def reviewer(state: LinkingState) -> LinkingState:
    print("  [REVIEWER] Mereview proses linking...")

    linked_results = state.get("linked_results", [])

    total = len(linked_results)
    success = sum(1 for r in linked_results if r.get("status") == "success")
    failed = total - success
    total_triples = sum(r.get("triples_count", 0) for r in linked_results)

    summary_parts = [
        f"Linking selesai. {success} dari {total} tugas berhasil.",
        f"Total triple yang dihasilkan: {total_triples}.",
    ]

    if failed > 0:
        failed_types = [
            r["link_type"] for r in linked_results
            if r.get("status") != "success"
        ]
        summary_parts.append(
            f"Gagal: {failed} tugas ({', '.join(failed_types)})."
        )

    output_files = [
        r["output_file"] for r in linked_results
        if r.get("output_file")
    ]
    if output_files:
        summary_parts.append(
            f"File output: {', '.join(output_files)}"
        )

    summary = " ".join(summary_parts)
    print(f"  [REVIEWER] {summary}")

    return {
        "all_done": True,
        "messages": [AIMessage(content=summary)],
    }
