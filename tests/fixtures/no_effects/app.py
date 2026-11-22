from fastapi import APIRouter

router = APIRouter()


@router.get("/ping")
def ping():
    # No database object access at all.
    return {"status": "ok"}
