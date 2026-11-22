from fastapi import HTTPException

from models import Document


def load_with_early_return(session, doc_id, user, skip_check):
    document = session.get(Document, doc_id)
    if skip_check:
        return document
    if document.owner_id != user.id:
        raise HTTPException(404)
    return document


def check_row_owner(document, user):
    if document.owner_id != user.id:
        raise HTTPException(404)
