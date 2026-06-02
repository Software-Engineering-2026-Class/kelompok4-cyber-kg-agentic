from pathlib import Path
from ..state import ParserState

def planner(state: ParserState) -> ParserState:
    print("  [PLANNER] Analyzing available fetched datasets...")
    
    # Check the fetcher cache directory
    # Ensure this script is run from the project root or adjust path accordingly
    cache_dir = Path("fetcher_agent/cache")
    if not cache_dir.exists():
        print("  [PLANNER] Error: fetcher_agent/cache directory not found.")
        return state
        
    parse_plan = []
    
    # Scan cache directory for supported files
    for file_path in cache_dir.iterdir():
        if file_path.is_file() and file_path.suffix.lower() == ".json":
            source = file_path.stem.lower()
            
            # Read the json to see if it's a pointer
            try:
                import json
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                actual_file = str(file_path)
                parser_type = "json"
                
                # Check if it's a pointer like [{"source": "cwe", "file": "cache/cwec_v4.20.xml"}]
                if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict) and "file" in data[0]:
                    pointer_file = data[0]["file"].replace("\\", "/")
                    # If pointer_file is 'cache/cwec_v4.20.xml', we need to adjust it to 'fetcher_agent/cache/...'
                    # The pointer might be absolute or relative to fetcher_agent
                    if pointer_file.startswith("cache/"):
                        actual_file = str(Path("fetcher_agent") / pointer_file)
                    else:
                        actual_file = str(Path("fetcher_agent/cache") / Path(pointer_file).name)
                        
                    if actual_file.endswith(".xml"):
                        parser_type = "xml"
                        
            except Exception as e:
                print(f"  [PLANNER] Error reading {file_path.name}: {e}")
                continue
                
            parse_plan.append({
                "source": source,
                "file_path": actual_file,
                "parser_type": parser_type
            })
            print(f"  [PLANNER] Planned parsing for {source} using {parser_type} parser on {actual_file}.")

    if not parse_plan:
        print("  [PLANNER] No supported files found to parse.")
        
    # Pick the first task if available
    current_task = parse_plan.pop(0) if parse_plan else {}
    
    return {
        "parse_plan": parse_plan,
        "current_task": current_task
    }
