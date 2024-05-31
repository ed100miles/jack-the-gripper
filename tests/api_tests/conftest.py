import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlalchemy.pool import StaticPool

from jack_the_gripper.models import UserCreate, User
from jack_the_gripper.api.main import app
from jack_the_gripper.api.dependencies import get_session
from jack_the_gripper.api.route_utils.user_utils import pwd_context

DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool
)


@pytest.fixture(name="session")
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def override_get_session():
        yield session

    app.dependency_overrides[get_session] = override_get_session
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def user_data():
    return {
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "password123",
    }


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session, user_data):
    new_user = UserCreate(**user_data)
    user = User(
        username=new_user.username,
        email=new_user.email,
        hashed_password=pwd_context.hash(new_user.password),
    )
    session.add(user)
    session.commit()
    return user


@pytest.fixture(name="test_token")
def test_user_token_fixture(client, user_data, test_user):
    login_data = {"username": user_data["username"], "password": user_data["password"]}
    response = client.post("/users/token", data=login_data)
    token_data = response.json()
    return token_data["access_token"]
