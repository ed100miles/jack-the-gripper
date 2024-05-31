from os import getenv
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

import jwt
from dotenv import load_dotenv
from passlib.context import CryptContext
from fastapi import HTTPException
from sqlalchemy.exc import NoResultFound, IntegrityError
from sqlmodel import Session, select

from jack_the_gripper.models import User, UserCreate, UserPublic, UserUpdate

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@dataclass(frozen=True)
class AuthConfig:
    SECRET_KEY: str
    DB_URL: str
    ALGORITHM: str = "HS256"

    @staticmethod
    def from_env() -> "AuthConfig":
        secret_key = getenv("SECRET_KEY")
        db_url = getenv("DB_URL")

        if secret_key is None:
            raise ValueError("SECRET_KEY environment variable is not set")

        if db_url is None:
            raise ValueError("DB_URL environment variable is not set")

        return AuthConfig(SECRET_KEY=secret_key, DB_URL=db_url)


auth_config = AuthConfig.from_env()


def create_user(new_user: UserCreate, session: Session) -> UserPublic:
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


def delete_user(session: Session, username: str) -> dict[str, str]:
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


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, auth_config.SECRET_KEY, algorithm=auth_config.ALGORITHM
    )
    return encoded_jwt
