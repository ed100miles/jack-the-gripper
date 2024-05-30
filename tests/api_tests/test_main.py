from sqlmodel import Session, select
from fastapi.testclient import TestClient

from jack_the_gripper.models import User


def test_user_signup(client: TestClient, user_data):
    response = client.post("/users/signup/", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == user_data["username"]
    assert data["email"] == user_data["email"]


def test_login_for_access_token(client: TestClient, user_data, test_user):
    login_data = {"username": user_data["username"], "password": user_data["password"]}
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"


def test_users_me(client: TestClient, user_data, test_token):
    # Use the token to access the protected endpoint
    headers = {"Authorization": f"Bearer {test_token}"}
    response = client.get("/users/me/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == user_data["username"]
    assert data["email"] == user_data["email"]


def test_delete_users_me(client: TestClient, session: Session, user_data, test_token):
    # Delete the user
    headers = {"Authorization": f"Bearer {test_token}"}
    response = client.delete("/users/me/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "User deleted successfully"

    # Verify the user is deleted
    statement = select(User).where(User.username == user_data["username"])
    result = session.exec(statement).all()
    assert len(result) == 0


def test_update_users_me(client: TestClient, session: Session, test_token):
    # Update the user
    update_data = {
        "username": "newusername",
        "email": "newemail@example.com",
        "password": "newpassword",
    }

    headers = {"Authorization": f"Bearer {test_token}"}
    response = client.put("/users/me/", json=update_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "newemail@example.com"
    assert data["username"] == "newusername"

    # Verify the user is updated in the database
    updated_user = session.exec(
        select(User).where(User.username == update_data["username"])
    ).one()
    assert updated_user.email == "newemail@example.com"
    assert updated_user.username == "newusername"
