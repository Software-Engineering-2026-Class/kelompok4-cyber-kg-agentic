from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from state import FetcherState
from config import SOURCE_DESCRIPTIONS, FETCHER_REGISTRY
import json
from dotenv import load_dotenv

load_dotenv()
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

def planner(state: FetcherState) -> FetcherState:
    sources_summary = "\n".join([
        f"- {name}: {desc}"
        for name, desc in SOURCE_DESCRIPTIONS.items()
    ])

    user_instruction = state["messages"][-1].content

    print(f"\n[Planner] Membaca instruksi: '{user_instruction}'")

    response = llm.invoke([
        SystemMessage(content=f"""
Kamu adalah planner untuk sistem fetch data cybersecurity.
Tugasmu: tentukan sumber mana yang harus difetch berdasarkan instruksi user.

Sumber yang tersedia:
{sources_summary}

Balas HANYA dengan JSON array nama sumber. Tidak ada teks lain.
Contoh: ["cve", "cwe", "capec"]

Aturan:
- Kalau user minta semua → include semua
- Kalau user sebut sumber spesifik → hanya itu
- Urutan: sumber yang lebih sering update didahulukan
        """),
        HumanMessage(content=f"Instruksi: {user_instruction}")
    ])

    try:
        # Bersihkan response kalau ada backtick
        content = response.content.strip().strip("```json").strip("```").strip()
        plan = json.loads(content)
        # Validasi nama sumber
        plan = [s for s in plan if s in FETCHER_REGISTRY]
    except Exception as e:
        print(f"  [Planner] Gagal parse JSON ({e}), pakai semua sumber")
        plan = list(FETCHER_REGISTRY.keys())

    print(f"[Planner] Plan: {plan}")

    return {
        **state,
        "fetch_plan":     plan,
        "current_source": plan[0] if plan else "",
        "results":        [],
        "all_done":       False,
    }
