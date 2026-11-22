from fastapi import Depends, HTTPException

from .models import Flow


def get_session(): ...


def get_current_user(): ...


async def get_flow(flow_id: int, current_user=Depends(get_current_user), session=Depends(get_session)):
    flow = await session.get(Flow, flow_id)
    if not flow or flow.user_id != current_user.id:
        raise HTTPException(status_code=404)
    return flow
