from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class ThreatIntelLookupRequest(BaseModel):
    ip_address: str = Field(min_length=1, max_length=64)


class ThreatIntelResponse(BaseModel):
    id: int
    ip_address: str
    country: str | None
    asn: str | None
    reputation_score: int
    is_malicious: bool
    threat_categories: str | None
    source: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

