from datetime import datetime
from sqlmodel import Field, SQLModel, UniqueConstraint

#################################
##### Authentication models #####
#################################


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str


class UserBase(SQLModel):
    username: str
    email: str


class User(UserBase, table=True):
    __table_args__ = (UniqueConstraint("email", "username"), {"extend_existing": True})
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


#################################
######## Exercise models ########
#################################


class Metric(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    id: int | None = Field(default=None, primary_key=True)
    weight_kgs: float | None = None
    duration_secs: float | None = None
    edge_mm: int | None = None
    reps: int | None = None


class Exercise(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("name"), {"extend_existing": True})
    id: int | None = Field(default=None, primary_key=True)
    metric_id: int = Field(foreign_key="metric.id")
    workout_id: int | None = Field(default=None, foreign_key="workout.id")
    name: str
    description: str | None = None


class Record(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    exercise_id: int = Field(foreign_key="exercise.id")
    value: float
    completed_at: datetime | None = Field(default_factory=datetime.now)


class Workout(SQLModel, table=True):
    __table_args__ = {"extend_existing": True}
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
