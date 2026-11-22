from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str


class Flow(SQLModel, table=True):
    id: int = Field(primary_key=True)
    user_id: int
    name: str


class Record(SQLModel, table=True):
    id: int = Field(primary_key=True)
    payload: str
