from datetime import datetime

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field


class HuntQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2048)
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=200)


class HuntQueryResponse(BaseModel):
    query: str
    parsed: dict
    items: list[dict]
    total: int
    skip: int
    limit: int

    model_config = ConfigDict(from_attributes=True)


class SavedHuntQueryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=2048)


class SavedHuntQueryResponse(BaseModel):
    id: int
    name: str
    query: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

