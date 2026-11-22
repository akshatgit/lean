from fastapi import HTTPException

from models import Document, User


def load_owned_document(session, doc_id: int, user: User):
    document = session.get(Document, doc_id)
    if document.owner_id != user.id:
        raise HTTPException(404)
    return document
