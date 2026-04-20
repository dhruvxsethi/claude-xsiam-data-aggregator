from abc import ABC, abstractmethod
from typing import List
from normalizer.schema import ThreatEvent
from loguru import logger


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    async def collect(self, days: int = 1) -> List[ThreatEvent]:
        """Fetch raw data from the source and return normalised ThreatEvent list."""
        ...

    def _log(self, msg: str) -> None:
        logger.info(f"[{self.name}] {msg}")

    def _warn(self, msg: str) -> None:
        logger.warning(f"[{self.name}] {msg}")
