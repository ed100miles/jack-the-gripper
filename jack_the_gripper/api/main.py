from os import getenv
from typing import Annotated
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from sqlalchemy.exc import NoResultFound, IntegrityError
from passlib.context import CryptContext
from dotenv import load_dotenv

from jack_the_gripper.models import (
    User,
    UserPublic,
    UserCreate,
    UserUpdate,
    TokenData,
    Token,
)
from jack_the_gripper.db_utils import get_session

load_dotenv()


SECRET_KEY = getenv("SECRET_KEY")
assert SECRET_KEY is not None
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()


def create_user(new_user: UserCreate, session: Session):
    user = User(
        username=new_user.username,
        email=new_user.email,
        hashed_password=pwd_context.hash(new_user.password),
    )
    try:
        session.add(user)
        session.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=400, detail="User with that username or email already exists"
        )
    return UserPublic.model_validate(user)


def get_user(session: Session, username: str) -> User:
    try:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one()
    except NoResultFound:
        raise HTTPException(status_code=400, detail="Username not found")
    return user


def delete_user(session: Session, username: str):
    user = get_user(session, username)
    session.delete(user)
    session.commit()
    return {"detail": "User deleted successfully"}


def update_user(session: Session, username: str, new_data: UserUpdate) -> UserPublic:
    user = get_user(session, username)
    user.username = new_data.username if new_data.username else user.username
    user.email = new_data.email if new_data.email else user.email
    user.hashed_password = (
        pwd_context.hash(new_data.password)
        if new_data.password
        else user.hashed_password
    )
    session.commit()
    return UserPublic.model_validate(user)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(session: Session, username: str, password: str) -> User:
    user = get_user(session, username)
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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


@app.post("/users/token/")
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


@app.get("/users/me/", response_model=UserPublic)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return UserPublic.model_validate(current_user)


@app.delete("/users/me/")
async def delete_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    return delete_user(session, current_user.username)


@app.post("/users/signup/", response_model=UserPublic)
async def create_new_user(
    new_user: UserCreate,
    session: Annotated[Session, Depends(get_session)],
):
    return create_user(new_user, session)

@app.put("/users/me/", response_model=UserPublic)
async def update_users_me(
    new_data: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    return update_user(session, current_user.username, new_data)
