from uuid import UUID, uuid4

from pydantic import BaseModel, Field as SchemaField
from sqlmodel import Field, SQLModel


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    title: str


class DocOut(BaseModel):
    id: int
    title: str


class Receipt(BaseModel):
    id: UUID = SchemaField(default_factory=uuid4)
