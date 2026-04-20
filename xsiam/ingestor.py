import httpx
import json
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential
from loguru import logger

from normalizer.schema import ThreatEvent
from config import settings

# Max events per POST
BATCH_SIZE = 500


class XSIAMIngestor:

    def __init__(self) -> None:
        self._url = settings.xsiam_base_url   # full URL from the HTTP collector screen
        self._api_key = settings.xsiam_api_key

    def _headers(self) -> dict:
        return {
            "Authorization": self._api_key,
            "Content-Type": "text/plain",
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=15))
    async def _post_batch(self, client: httpx.AsyncClient, batch: List[dict]) -> None:
        # One JSON object per line — XSIAM HTTP log collector format
        body = "\n".join(json.dumps(event) for event in batch)
        resp = await client.post(self._url, content=body.encode(), headers=self._headers(), timeout=30)
        resp.raise_for_status()

    async def ingest(self, events: List[ThreatEvent]) -> int:
        if not self._url or not self._api_key:
            logger.warning("[XSIAM] Missing XSIAM_BASE_URL or XSIAM_API_KEY — skipping ingestion")
            return 0

        if not events:
            logger.info("[XSIAM] No events to ingest")
            return 0

        dicts = [e.to_xsiam_dict() for e in events]
        batches = [dicts[i : i + BATCH_SIZE] for i in range(0, len(dicts), BATCH_SIZE)]

        pushed = 0
        async with httpx.AsyncClient() as client:
            for i, batch in enumerate(batches, 1):
                try:
                    await self._post_batch(client, batch)
                    pushed += len(batch)
                    logger.info(f"[XSIAM] Batch {i}/{len(batches)} pushed ({len(batch)} events)")
                except Exception as e:
                    logger.error(f"[XSIAM] Batch {i} failed after retries: {e}")

        logger.info(f"[XSIAM] Ingestion complete — {pushed}/{len(dicts)} events pushed")
        return pushed
