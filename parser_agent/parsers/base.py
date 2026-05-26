from abc import ABC, abstractmethod
from pathlib import Path

class BaseParser(ABC):
    def __init__(self, source_name: str, file_path: str):
        self.source_name = source_name
        self.file_path = Path(file_path)

    @abstractmethod
    def parse(self) -> list[dict]:
        """
        Parses the file and returns a list of raw entity dictionaries.
        """
        pass
