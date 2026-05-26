import json
import traceback
from pathlib import Path
from ..state import ParserState
from ..parsers.json_parser import JSONParser
from ..parsers.xml_parser import XMLParser
from ..ontology_mapper import OntologyMapper

def executor(state: ParserState) -> ParserState:
    task = state["current_task"]
    source = task["source"]
    file_path = task["file_path"]
    parser_type = task["parser_type"]
    
    print(f"  [EXECUTOR] Parsing {source} using {parser_type} parser...")
    
    result = {
        "source": source,
        "status": "failed",
        "entities_count": 0,
        "error": None,
        "output_file": None
    }
    
    try:
        # 1. Parse raw data
        if parser_type == "json":
            parser = JSONParser(source, file_path)
        elif parser_type == "xml":
            parser = XMLParser(source, file_path)
        else:
            raise ValueError(f"Unknown parser type: {parser_type}")
            
        raw_entities = parser.parse()
        print(f"  [EXECUTOR] Extracted {len(raw_entities)} raw entities from {source}.")
        
        # 2. Map to Ontology
        mapper = OntologyMapper()
        mapped_entities = []
        for raw in raw_entities:
            mapped = mapper.map_entity(source, raw)
            if mapped: # Only keep non-empty mappings
                mapped_entities.append(mapped)
                
        # 3. Save mapped entities to output directory
        out_dir = Path("parser_agent/output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{source}_mapped.json"
        
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(mapped_entities, f, indent=2)
            
        result["status"] = "success"
        result["entities_count"] = len(mapped_entities)
        result["output_file"] = str(out_file)
        print(f"  [EXECUTOR] Successfully mapped {len(mapped_entities)} entities. Saved to {out_file}.")
        
    except Exception as e:
        error_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"  [EXECUTOR] Error processing {source}: {error_msg}")
        result["error"] = str(e)
        
    parsed_results = state.get("parsed_results", [])
    parsed_results.append(result)
    
    # Get next task
    parse_plan = state.get("parse_plan", [])
    next_task = parse_plan.pop(0) if parse_plan else {}
    
    return {
        "parse_plan": parse_plan,
        "current_task": next_task,
        "parsed_results": parsed_results
    }
