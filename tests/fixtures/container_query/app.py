from fastapi import APIRouter, Depends
from sqlalchemy import select

from models import Document


def get_db():
    pass


router = APIRouter()


@router.get("/docs")
def list_docs(db=Depends(get_db)):
    # The query is wrapped in list(...); its read effect must still be modeled.
    rows = list(db.exec(select(Document)))
    return rows
