from fastapi import APIRouter, Depends, FastAPI, Security

from child import router as child_router
from explicit_child import router as explicit_child_router
from models import Document


def get_current_user():
    pass


def get_db():
    pass


router = APIRouter(dependencies=[Depends(get_current_user)])
db_only_router = APIRouter(dependencies=[Depends(get_db)])
app = FastAPI(dependencies=[Depends(get_current_user)])
public_app = FastAPI()
app.include_router(child_router)
public_app.include_router(explicit_child_router, dependencies=[Depends(get_current_user)])


@router.get("/router-auth/{doc_id}")
def router_authenticated(doc_id: int, session=Depends(get_db)):
    return session.get(Document, doc_id)


@db_only_router.get("/db-only/{doc_id}")
def database_dependency_only(doc_id: int, session=Depends(get_db)):
    return session.get(Document, doc_id)


@db_only_router.get("/security/{doc_id}")
def security_argument(doc_id: int, current_user=Security(get_current_user), session=Depends(get_db)):
    return session.get(Document, doc_id)


@app.get("/app-auth/{doc_id}")
def app_authenticated(doc_id: int, session=Depends(get_db)):
    return session.get(Document, doc_id)
