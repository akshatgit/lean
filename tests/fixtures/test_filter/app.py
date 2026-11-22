from fastapi import APIRouter

router = APIRouter()


@router.get("/production")
def production_route():
    return {"ok": True}
