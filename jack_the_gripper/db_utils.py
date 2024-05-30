from dotenv import load_dotenv
from sqlmodel import create_engine, Session
from os import getenv

load_dotenv()

db_url = getenv("DB_URL")
assert db_url is not None

engine = create_engine(db_url, echo=True)


def get_session():
    with Session(engine) as session:
        yield session
