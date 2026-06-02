class OntologyMapper:
    """
    Maps parsed raw entity dictionaries to SEPSES ontology classes.
    """

    def map_entity(self, source_name: str, raw_entity: dict) -> dict:
        mapped = {}
        
        if source_name == "cve":
            mapped["@type"] = "sepses:CVE"
            # NVD 2.0 format typically nests cve inside a dictionary
            cve_data = raw_entity.get("cve", {})
            mapped["sepses:id"] = cve_data.get("id")
            
            # Map descriptions
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    mapped["sepses:description"] = desc.get("value")
                    break
            
            # Map weaknesses (CWEs)
            weaknesses = cve_data.get("weaknesses", [])
            cwe_refs = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("value") and desc.get("value").startswith("CWE-"):
                        cwe_refs.append(f"sepses:{desc.get('value')}")
            if cwe_refs:
                mapped["sepses:hasCWE"] = cwe_refs
                
        elif source_name == "cwe":
            mapped["@type"] = "sepses:CWE"
            attribs = raw_entity.get("attribs", {})
            mapped["sepses:id"] = f"CWE-{attribs.get('ID')}"
            mapped["sepses:name"] = attribs.get("Name")
            if "Description" in raw_entity:
                mapped["sepses:description"] = raw_entity["Description"]
                
        elif source_name == "cpe":
            mapped["@type"] = "sepses:CPE"
            cpe_data = raw_entity.get("cpe", {})
            mapped["sepses:id"] = cpe_data.get("cpeNameId")
            mapped["sepses:cpe23Uri"] = cpe_data.get("cpeName")
            
        elif source_name == "capec":
            mapped["@type"] = "sepses:CAPEC"
            attribs = raw_entity.get("attribs", {})
            mapped["sepses:id"] = f"CAPEC-{attribs.get('ID')}"
            mapped["sepses:name"] = attribs.get("Name")
            if "Description" in raw_entity:
                mapped["sepses:description"] = raw_entity["Description"]

        elif source_name == "icsa":
            # Assuming ICSA structure from known exploited vulnerabilities
            mapped["@type"] = "sepses:ICSA"
            mapped["sepses:cveID"] = raw_entity.get("cveID")
            mapped["sepses:vendorProject"] = raw_entity.get("vendorProject")
            mapped["sepses:product"] = raw_entity.get("product")
            mapped["sepses:vulnerabilityName"] = raw_entity.get("vulnerabilityName")

        elif source_name.startswith("attck"):
            mapped["@type"] = "sepses:AttackPattern"
            if raw_entity.get("type") == "attack-pattern":
                
                # Skip entitas yang sudah revoked atau deprecated
                if raw_entity.get("revoked") or raw_entity.get("x_mitre_deprecated"):
                    return {}
                    
                mapped["sepses:id"] = raw_entity.get("id")
                mapped["sepses:name"] = raw_entity.get("name")
                mapped["sepses:description"] = raw_entity.get("description")

                for ext_ref in raw_entity.get("external_references", []):
                    if ext_ref.get("source_name") == "mitre-attack":
                        mapped["sepses:techniqueId"] = ext_ref.get("external_id")
                        mapped["__uri_key__"] = ext_ref.get("external_id")
                        break
            else:
                return {}

        else:
            mapped["@type"] = "sepses:Unknown"
            mapped["raw_data"] = raw_entity

        # Remove None values
        return {k: v for k, v in mapped.items() if v is not None}
