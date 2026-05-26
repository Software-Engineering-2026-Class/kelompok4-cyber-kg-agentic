from graph import graph

print("=" * 50)
print("  FETCHER AGENT — Cybersecurity KG Pipeline")
print("=" * 50)

# Ganti instruksi di bawah sesuai kebutuhan:
instruksi = "Fetch data CVE dan CWE cybersecurity yang tersedia."
# instruksi = "Fetch semua data cybersecurity yang tersedia."
# instruksi = "Saya butuh data CVE dan CWE untuk analisis kerentanan."

print(f"\nInstruksi: {instruksi}\n")

result = graph.invoke({
    "messages":       [{"role": "user", "content": instruksi}],
    "fetch_plan":     [],
    "current_source": "",
    "results":        [],
    "all_done":       False,
})

print("\n" + "=" * 50)
print("  HASIL AKHIR")
print("=" * 50)

success = [r for r in result["results"] if r["status"] in ("success", "cached")]
failed  = [r for r in result["results"] if r["status"] == "failed"]

for r in result["results"]:
    icon = "✓" if r["status"] in ("success", "cached") else "✗"
    print(f"\n{icon} {r['source'].upper()}")
    print(f"   Status  : {r['status']}")
    print(f"   Records : {r.get('records', 0):,}")
    if r["file_path"]:
        print(f"   File    : {r['file_path']}")
    if r["error"]:
        print(f"   Error   : {r['error']}")

print(f"\n{'─'*50}")
print(f"Berhasil : {len(success)} sumber")
print(f"Gagal    : {len(failed)} sumber")
print(f"\nRingkasan: {result['messages'][-1].content}")
