from pydantic import BaseModel
from sqlmodel import Field, SQLModel


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    title: str


class DocOut(BaseModel):
    id: int
    title: str
