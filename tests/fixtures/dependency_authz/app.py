from fastapi import APIRouter, Depends

from deps import get_document, get_document_unchecked
from models import Document

router = APIRouter(prefix="/api")


@router.get("/documents/{doc_id}")
def read_document(doc: Document = Depends(get_document)):
    # Authorization lives entirely in the get_document dependency.
    return doc


@router.get("/leaky/{doc_id}")
def read_leaky(doc: Document = Depends(get_document_unchecked)):
    # Dependency loads the row by id but never checks ownership.
    return doc
