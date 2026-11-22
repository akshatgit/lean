"""Demo API with known-vulnerable and fixed endpoints.

Expected verdicts (see tests/test_demo.py):
  GET    /api/v1/documents/{doc_id}         VIOLATION  loads by id only
  GET    /api/v2/documents/{doc_id}         SAFE       guard after load
  GET    /api/v3/documents/{doc_id}         SAFE       owner filter in the query
  GET    /api/v1/public/{doc_id}            SAFE       public documents only
  PUT    /api/v1/documents/{doc_id}         SAFE       guarded update
  DELETE /api/v1/documents/{doc_id}         VIOLATION  delete without owner check
  POST   /api/v1/documents                  VIOLATION  owner_id taken from the request body
  POST   /api/v2/documents                  SAFE       owner_id from the caller
  GET    /api/v1/storage/{doc_id}           VIOLATION  helper summary says: by id only (assumed)
  GET    /api/v1/export/{doc_id}            UNKNOWN    helper with no source and no summary
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

import storage          # pretend: installed package, no source available
import exporter         # pretend: installed package, no source available
from deps import get_current_user, get_db
from models import Document, User

router = APIRouter(prefix="/api")


class DocIn(BaseModel):
    title: str
    owner_id: int


class DocTitle(BaseModel):
    title: str


@router.get("/v1/documents/{doc_id}")
def get_doc_v1(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(404)
    return doc


@router.get("/v2/documents/{doc_id}")
def get_doc_v2(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    return doc


@router.get("/v3/documents/{doc_id}")
def get_doc_v3(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.execute(
        select(Document).where(Document.id == doc_id, Document.owner_id == user.id)
    ).scalar_one_or_none()
    if not doc:
        raise HTTPException(404)
    return doc


@router.get("/v1/public/{doc_id}")
def get_public(doc_id: int, db: Session = Depends(get_db)):
    return db.query(Document).filter(Document.id == doc_id, Document.visibility == "public").first()


@router.put("/v1/documents/{doc_id}")
def rename_doc(doc_id: int, body: DocTitle, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    doc.title = body.title
    db.commit()
    return doc


@router.delete("/v1/documents/{doc_id}")
def delete_doc(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(404)
    db.delete(doc)
    db.commit()


@router.post("/v1/documents")
def create_doc_v1(body: DocIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = Document(title=body.title, owner_id=body.owner_id)
    db.add(doc)
    db.commit()
    return doc


@router.post("/v2/documents")
def create_doc_v2(body: DocTitle, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = Document(title=body.title, owner_id=user.id)
    db.add(doc)
    db.commit()
    return doc


@router.get("/v1/storage/{doc_id}")
def get_from_storage(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return storage.load_doc(db, doc_id)


@router.get("/v1/export/{doc_id}")
def export_doc(doc_id: int, user: User = Depends(get_current_user)):
    return exporter.render(doc_id)
