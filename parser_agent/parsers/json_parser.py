import json
from .base import BaseParser

class JSONParser(BaseParser):
    def parse(self) -> list[dict]:
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entities = []
        if self.source_name == "cve":
            if isinstance(data, dict) and "vulnerabilities" in data:
                entities = data["vulnerabilities"]
            elif isinstance(data, list):
                entities = data
        elif self.source_name == "cpe":
            if isinstance(data, dict) and "products" in data:
                entities = data["products"]
            elif isinstance(data, list):
                entities = data
        elif self.source_name == "icsa":
            if isinstance(data, dict) and "vulnerabilities" in data:
                entities = data["vulnerabilities"]
            elif isinstance(data, list):
                entities = data
        elif self.source_name.startswith("attck"):
            if isinstance(data, dict) and "objects" in data:
                entities = data["objects"]
            elif isinstance(data, list):
                entities = data
        else:
            # Fallback for generic JSON
            if isinstance(data, list):
                entities = data
            elif isinstance(data, dict):
                entities = [data]

        return entities
