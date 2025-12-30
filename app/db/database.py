from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

#motor de base de datos SQLAlchemy
engine = create_engine(
    settings.database_url,
    echo=True,
)
#Objeto sessionmaker de SQLAlchemy
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
