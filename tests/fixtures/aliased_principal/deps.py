from typing import Annotated

from fastapi import Depends

from models import User


def get_current_active_user():
    pass


def get_db():
    pass


CurrentActiveUser = Annotated[User, Depends(get_current_active_user)]
DbSession = Annotated[object, Depends(get_db)]
