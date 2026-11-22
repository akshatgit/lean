import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select

from models import Document, User

router = APIRouter()
logger = logging.getLogger(__name__)


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
    result = await session.exec(
        select(Document).where(Document.id == doc_id, Document.owner_id == user.id)
    )
    document = result.first()
    logger.info("read document %s", document.id)
    return JSONResponse({"id": str(document.id)})
