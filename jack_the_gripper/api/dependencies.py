import jwt
from sqlmodel import create_engine, Session
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, status, Depends
from typing import Annotated

from jack_the_gripper.models import User, TokenData
from jack_the_gripper.api.route_utils.user_utils import get_user, auth_config


engine = create_engine(auth_config.DB_URL, echo=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token")


def get_session():
    with Session(engine) as session:
        yield session


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, auth_config.SECRET_KEY, algorithms=[auth_config.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(session, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user
