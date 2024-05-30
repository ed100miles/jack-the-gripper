from sqlmodel import Field, SQLModel, UniqueConstraint


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str


class UserBase(SQLModel):
    username: str
    email: str


class User(UserBase, table=True):
    __table_args__ = (UniqueConstraint("email", "username"),)
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str


class UserCreate(UserBase):
    password: str


class UserUpdate(UserBase):
    username: str | None = None
    email: str | None = None
    password: str | None = None


class UserPublic(UserBase):
    id: int
