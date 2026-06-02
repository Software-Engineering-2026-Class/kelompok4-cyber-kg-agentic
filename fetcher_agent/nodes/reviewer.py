from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from state import FetcherState
import json
from dotenv import load_dotenv

load_dotenv()
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

def reviewer(state: FetcherState) -> FetcherState:
    retry_count = state.get("retry_count", 0)
    MAX_RETRIES = 2

    results_summary = "\n".join([
        f"- {r['source']}: {r['status']}"
        + (f", {r['records']} records, file: {r['file_path']}"
           if r["status"] != "failed" else f", ERROR: {r['error']}")
        for r in state["results"]
    ])

    print(f"\n[Reviewer] Mengevaluasi hasil... (retry ke-{retry_count})")

    response = llm.invoke([
        SystemMessage(content="""
Kamu adalah reviewer hasil fetch data cybersecurity.
Evaluasi hasil dan putuskan apakah ada yang perlu diretry.

Balas HANYA dengan JSON berikut (tidak ada teks lain):
{
  "verdict": "done",
  "retry_sources": [],
  "summary": "ringkasan singkat dalam Bahasa Indonesia"
}

Aturan:
- verdict = "retry" hanya kalau ada status "failed"
- Jangan retry sumber yang sudah "success" atau "cached"
- summary: ringkasan ramah untuk user, sebutkan berapa sumber berhasil
        """),
        HumanMessage(content=f"Hasil fetch:\n{results_summary}")
    ])

    try:
        content = response.content.strip().strip("```json").strip("```").strip()
        verdict = json.loads(content)
    except Exception:
        verdict = {
            "verdict": "done",
            "retry_sources": [],
            "summary": response.content
        }

    print(f"[Reviewer] Verdict: {verdict['verdict']}")

    if verdict["verdict"] == "retry" and verdict.get("retry_sources") and retry_count < MAX_RETRIES:
        retry_plan = [s for s in verdict["retry_sources"] if s in state["fetch_plan"]]
        if retry_plan:
            return {
                **state,
                "fetch_plan":     retry_plan,
                "current_source": retry_plan[0],
                "all_done":       False,
                "retry_count":    retry_count + 1,
                "messages": state["messages"] + [
                    AIMessage(content=f"Mencoba retry untuk: {retry_plan}")
                ],
            }

    return {
        **state,
        "all_done": True,
        "retry_count": 0,
        "messages": state["messages"] + [
            AIMessage(content=verdict["summary"])
        ],
    }