import json
import traceback
from pathlib import Path
from ..state import ParserState
from ..parsers.json_parser import JSONParser
from ..parsers.xml_parser import XMLParser

def executor(state: ParserState) -> ParserState:
    task = state.get("current_task")
    if not task:
        print("  [EXECUTOR] No task to execute.")
        parsed_results = state.get("parsed_results", [])
        parse_plan = state.get("parse_plan", [])
        next_task = parse_plan.pop(0) if parse_plan else {}
        return {
            "parse_plan": parse_plan,
            "current_task": next_task,
            "parsed_results": parsed_results
        }
        
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
        # 1. Parse raw data to count entities
        if parser_type == "json":
            parser = JSONParser(source, file_path)
        elif parser_type == "xml":
            parser = XMLParser(source, file_path)
        else:
            raise ValueError(f"Unknown parser type: {parser_type}")
            
        raw_entities = parser.parse()
        print(f"  [EXECUTOR] Extracted {len(raw_entities)} raw entities from {source}.")
        
        # 2. Generate RML mapping content
        rml_content = ""
        source_key = source.lower()
        if source_key == "cve":
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/cve#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#CVEMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:JSONPath ;
        rml:iterator "$.vulnerabilities[*]"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/cve/{{cve.id}}" ;
        rr:class sepses:CVE
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:id ;
        rr:objectMap [ rml:reference "cve.id" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:description ;
        rr:objectMap [ rml:reference "cve.descriptions[?(@.lang=='en')].value" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:hasCWE ;
        rr:objectMap [ rml:reference "cve.weaknesses[*].description[?(@.lang=='en')].value" ]
    ] .
"""
        elif source_key == "cwe":
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/cwe#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#CWEMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:XPath ;
        rml:iterator "/Weakness_Catalog/Weaknesses/Weakness"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/cwe/CWE-{{@ID}}" ;
        rr:class sepses:CWE
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:id ;
        rr:objectMap [ rr:template "CWE-{{@ID}}" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:name ;
        rr:objectMap [ rml:reference "@Name" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:description ;
        rr:objectMap [ rml:reference "Description" ]
    ] .
"""
        elif source_key == "cpe":
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/cpe#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#CPEMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:JSONPath ;
        rml:iterator "$.products[*]"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/cpe/{{cpe.cpeNameId}}" ;
        rr:class sepses:CPE
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:id ;
        rr:objectMap [ rml:reference "cpe.cpeNameId" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:cpe23Uri ;
        rr:objectMap [ rml:reference "cpe.cpeName" ]
    ] .
"""
        elif source_key == "capec":
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/capec#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#CAPECMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:XPath ;
        rml:iterator "/Attack_Pattern_Catalog/Attack_Patterns/Attack_Pattern"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/capec/CAPEC-{{@ID}}" ;
        rr:class sepses:CAPEC
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:id ;
        rr:objectMap [ rr:template "CAPEC-{{@ID}}" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:name ;
        rr:objectMap [ rml:reference "@Name" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:description ;
        rr:objectMap [ rml:reference "Description" ]
    ] .
"""
        elif source_key == "icsa":
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/icsa#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#ICSAMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:JSONPath ;
        rml:iterator "$.vulnerabilities[*]"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/icsa/{{cveID}}" ;
        rr:class sepses:ICSA
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:cveID ;
        rr:objectMap [ rml:reference "cveID" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:vendorProject ;
        rr:objectMap [ rml:reference "vendorProject" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:product ;
        rr:objectMap [ rml:reference "product" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:vulnerabilityName ;
        rr:objectMap [ rml:reference "vulnerabilityName" ]
    ] .
"""
        elif source_key.startswith("attck"):
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/attack#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#ATTCKMapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:JSONPath ;
        rml:iterator "$.objects[?(@.type=='attack-pattern')]"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/attack/{{id}}" ;
        rr:class sepses:AttackPattern
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:id ;
        rr:objectMap [ rml:reference "id" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:name ;
        rr:objectMap [ rml:reference "name" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:description ;
        rr:objectMap [ rml:reference "description" ]
    ] ;
    rr:predicateObjectMap [
        rr:predicate sepses:techniqueId ;
        rr:objectMap [ rml:reference "external_references[?(@.source_name=='mitre-attack')].external_id" ]
    ] .
"""
        else:
            # Fallback mapping
            rml_content = f"""@prefix rr: <http://www.w3.org/ns/r2rml#> .
@prefix rml: <http://semweb.mmlab.be/ns/rml#> .
@prefix ql: <http://semweb.mmlab.be/ns/ql#> .
@prefix sepses: <http://w3id.org/sepses/vocab/ref/{source_key}#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<#{source_key.upper()}Mapping> a rr:TriplesMap ;
    rml:logicalSource [
        rml:source "{file_path}" ;
        rml:referenceFormulation ql:JSONPath ;
        rml:iterator "$"
    ] ;
    rr:subjectMap [
        rr:template "http://w3id.org/sepses/resource/{source_key}/{{id}}" ;
        rr:class sepses:Unknown
    ] .
"""

        # 3. Save RML rules to output directory
        out_dir = Path("parser_agent/output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{source}.rml"
        
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(rml_content)
            
        result["status"] = "success"
        result["entities_count"] = len(raw_entities)
        result["output_file"] = str(out_file)
        print(f"  [EXECUTOR] Successfully generated RML mapping rules. Saved to {out_file}.")
        
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

