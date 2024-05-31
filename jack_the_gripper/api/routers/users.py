from typing import Annotated
from datetime import timedelta

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session

from jack_the_gripper.models import (
    User,
    UserPublic,
    UserCreate,
    UserUpdate,
    Token,
)
from ..dependencies import get_session, get_current_user
from ..route_utils.user_utils import (
    authenticate_user,
    create_access_token,
    create_user,
    delete_user,
    update_user,
)


ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserPublic)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return UserPublic.model_validate(current_user)


@router.delete("/me")
async def delete_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    return delete_user(session, current_user.username)


@router.post("/signup", response_model=UserPublic)
async def create_new_user(
    new_user: UserCreate,
    session: Annotated[Session, Depends(get_session)],
):
    return create_user(new_user, session)


@router.put("/me", response_model=UserPublic)
async def update_users_me(
    new_data: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    return update_user(session, current_user.username, new_data)
