from fastapi import APIRouter

from ..config import get_settings

router = APIRouter(prefix="/capabilities", tags=["capabilities"])


@router.get("/ai")
async def ai_capabilities():
    """Return whether AI features are available (i.e. LLM_API_KEY is configured)."""
    return {"available": get_settings().ai_available}
