from fastapi import APIRouter, Depends

from helpers import load_owned_document
from models import User

router = APIRouter()


def get_current_user():
    pass


def get_db():
    pass


@router.get("/documents/{doc_id}")
def read_document(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    return load_owned_document(session, doc_id, user)
