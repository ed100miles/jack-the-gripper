from fastapi import FastAPI

from ..logger import logger
from .routers import users

logger.info("Starting API...")

app = FastAPI()
app.include_router(users.router)
