import json
from pathlib import Path
from ..state import LinkingState
from ..config import LINKING_RULES


def planner(state: LinkingState) -> LinkingState:
    print("  [PLANNER] Menganalisis output parser_agent untuk perencanaan linking...")

    parser_output_dir = Path("parser_agent/output")
    fetcher_cache_dir = Path("fetcher_agent/cache")

    available_sources = set()

    if parser_output_dir.exists():
        for rml_file in parser_output_dir.iterdir():
            if rml_file.is_file() and rml_file.suffix == ".rml":
                source_name = rml_file.stem.lower()
                available_sources.add(source_name)
                print(f"  [PLANNER] Ditemukan output parser: {source_name} ({rml_file.name})")
    else:
        print("  [PLANNER] WARNING: Direktori parser_agent/output tidak ditemukan.")

    if not available_sources and fetcher_cache_dir.exists():
        print("  [PLANNER] Mencoba membaca langsung dari fetcher_agent/cache...")
        for cache_file in fetcher_cache_dir.iterdir():
            if cache_file.is_file():
                source_name = cache_file.stem.lower()
                available_sources.add(source_name)
                print(f"  [PLANNER] Ditemukan cache: {source_name} ({cache_file.name})")

    print(f"  [PLANNER] Sumber data tersedia: {sorted(available_sources)}")

    link_plan = []

    for rule in LINKING_RULES:
        subject_src = rule["subject_src"]
        object_src = rule["object_src"]

        subject_available = any(
            s == subject_src or s.startswith(subject_src) for s in available_sources
        )
        object_available = any(
            s == object_src or s.startswith(object_src) for s in available_sources
        )

        if subject_available and object_available:
            subject_files = _find_data_files(fetcher_cache_dir, subject_src)
            object_files = _find_data_files(fetcher_cache_dir, object_src)

            task = {
                "link_type":    rule["link_type"],
                "subject_src":  subject_src,
                "object_src":   object_src,
                "predicate":    rule["predicate"],
                "description":  rule["description"],
                "subject_files": subject_files,
                "object_files":  object_files,
            }
            link_plan.append(task)
            print(f"  [PLANNER] ✓ Direncanakan: {rule['link_type']} "
                  f"({rule['predicate']})")
        else:
            missing = []
            if not subject_available:
                missing.append(subject_src)
            if not object_available:
                missing.append(object_src)
            print(f"  [PLANNER] ✗ Dilewati: {rule['link_type']} "
                  f"(sumber tidak tersedia: {', '.join(missing)})")

    if not link_plan:
        print("  [PLANNER] Tidak ada tugas linking yang dapat direncanakan.")

    current_task = link_plan.pop(0) if link_plan else {}

    return {
        "link_plan": link_plan,
        "current_task": current_task,
    }


def _find_data_files(cache_dir: Path, source_prefix: str) -> list[str]:
    files = []
    if not cache_dir.exists():
        return files

    for f in cache_dir.iterdir():
        if not f.is_file():
            continue

        stem = f.stem.lower()
        if stem == source_prefix or stem.startswith(source_prefix):
            if f.suffix.lower() == ".json":
                try:
                    with open(f, "r", encoding="utf-8") as fp:
                        data = json.load(fp)
                    if (isinstance(data, list) and len(data) == 1
                            and isinstance(data[0], dict) and "file" in data[0]):
                        pointer_file = data[0]["file"]
                        if pointer_file.startswith("cache/"):
                            actual = str(Path("fetcher_agent") / pointer_file)
                        else:
                            actual = str(Path("fetcher_agent/cache") / Path(pointer_file).name)

                        resolved = Path(actual).resolve()
                        safe_base = Path("fetcher_agent").resolve()
                        if not str(resolved).startswith(str(safe_base)):
                            print(f"  [PLANNER] WARNING: Path traversal terdeteksi, "
                                  f"melewati pointer: {pointer_file}")
                            continue

                        files.append(actual)
                        continue
                except (json.JSONDecodeError, IOError):
                    pass

            files.append(str(f))

    return files
