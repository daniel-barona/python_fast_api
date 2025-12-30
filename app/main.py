from fastapi import FastAPI
from app.db.database import SessionLocal
from app.core.startup import create_initial_user
from app.api.auth import router as auth_router
from app.api.tasks import router as tasks_router


app = FastAPI()


@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        create_initial_user(db)
    finally:
        db.close()
app.include_router(auth_router)
app.include_router(tasks_router)
