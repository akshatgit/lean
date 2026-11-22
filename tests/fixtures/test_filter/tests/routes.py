from fastapi import APIRouter

router = APIRouter()


@router.get("/test-only")
def test_route():
    return {"ok": True}
