from fastapi import APIRouter, Depends
from sqlalchemy import select

from models import Document, User

router = APIRouter()


def get_current_user():
    pass


def get_db():
    pass


@router.get("/documents/{doc_id}")
async def read_document(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    stmt = select(Document)
    stmt = stmt.where(Document.id == doc_id)
    stmt = stmt.where(Document.owner_id == user.id)
    result = await session.exec(stmt)
    return result.first()
