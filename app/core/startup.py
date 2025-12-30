from sqlalchemy.orm import Session

from app.models.user import User
from app.core.security import hash_password
from app.core.config import settings


def create_initial_user(db: Session) -> None:
    user = db.query(User).filter(
        User.email == settings.FIRST_SUPERUSER_EMAIL
    ).first()

    if not user:
        user = User(
            email=settings.FIRST_SUPERUSER_EMAIL,
            hashed_password=hash_password(
                settings.FIRST_SUPERUSER_PASSWORD
            ),
            is_active=True,
        )
        db.add(user)
        db.commit()
        print("Usuario inicial creado")
    else:
        print("Usuario inicial ya existe")
