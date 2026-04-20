from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone


class ThreatEvent(BaseModel):
    """Normalized threat intelligence event — maps to XSIAM custom dataset fields."""

    # XSIAM requires _time in ISO 8601 (leading underscore not allowed on field names in Pydantic 2.11+)
    record_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        serialization_alias="_time",
    )

    # Source identification
    source_feed: str                          # e.g. "AlienVault OTX", "CISA KEV", "NVD"
    source_event_id: Optional[str] = None    # original ID from the feed

    # Event classification
    event_type: str                           # "ioc", "campaign", "vulnerability", "advisory"

    # Threat context
    threat_actor: Optional[str] = None
    threat_family: Optional[str] = None      # e.g. "Emotet", "QakBot", "Dridex"
    campaign_name: Optional[str] = None

    # Targeting
    target_sector: Optional[str] = None      # "banking", "finance", etc.
    target_country: Optional[str] = None

    # Attack details
    attack_vector: Optional[str] = None      # "phishing", "exploit", "watering_hole"
    mitre_tactic: Optional[str] = None       # e.g. "Initial Access"
    mitre_technique: Optional[str] = None    # e.g. "T1566.001"

    # IOC fields (populated when event_type == "ioc")
    ioc_type: Optional[str] = None           # "ip", "domain", "url", "hash_md5", "hash_sha256", "email"
    ioc_value: Optional[str] = None

    # Vulnerability fields (populated when event_type == "vulnerability")
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_product: Optional[str] = None

    # Severity
    severity: str = "medium"                 # "critical", "high", "medium", "low", "info"

    # Geography
    geo_origin: Optional[str] = None         # 2-letter country code of attacker origin

    # Description & metadata
    title: str
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    reference_url: Optional[str] = None

    # Cross-source deduplication — populated by pipeline when same IOC appears in multiple feeds
    seen_in: List[str] = Field(default_factory=list)

    def to_xsiam_dict(self) -> dict:
        """Serialise to a flat dict for XSIAM ingestion."""
        data = self.model_dump(by_alias=True)
        # Remove None values to keep payloads lean
        return {k: v for k, v in data.items() if v is not None and v != []}
