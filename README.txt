Este es un proyecto donde se implemento un API Restful para un CRUD de task

** TECNOLOGIAS UTILIZADAS ***
 -Python 3.11.8
 -Postgree 18
 -FASTAPI
 -SQLAlchemy
 -Alembic
 -JWT Authentication
 -Docker & Docker Compose
 -Swagger
 -Chatgpt

- Chatgpt se uso para problemas con las librerias (versiones puntuales), comentarios que se podran observar en requirements.txt

Como primera parte se recomienda crear un enviroment 
--> python3.11 -m venv tecnico
--> (Activarlo) --> .\tecnico\Scripts\activate (estar siempre en el enviroment)

Igualmente el enviroment se puede observar directamente en el repositorio
Para instalar las librerias vamos a proceder ejecutando el siguiente metodo:
--> pip install -r requirements.txt


Para traer el FAST API Y SQLAlchemy

Los archivos que se deben fijar (crearon) son 
- App/core/config.py: Es la configuracion central 
- db/database.py: realiza el motor (engine) y inicia la sesison
- db/base.py: Contiene el SQLAlchemy
-main.py: FAST API
-.env : Maneja las variables de entorno, con las que se va a realizar el login a la db y usuario a  registrar para configurar las task
-requirements.txt : Contiene todas la librerias a instalar durante el proceso (ver arriba para ejecutar el arhivo) --> pip install -r requirements.txt (una vez creado el enviroment)

Despues de eso procedemos a ejecutar el siguiente comando 

- python -m uvicorn app.main:app --reload  (-m es una abreviatura del modulo)

** Para trabajar con el Alembic **

En requirements esta el que se instalo 
 ** IMPORTANTE **
Revisar si se instalo correctamente:
--> alembic --version
Desde la raiz de proyecto que estamos realizando debemos ejecutar el siguiente comando 
--> alembic init app/db/migrations
Con la finalidad de empezar a migrar
Dando como resultado:
app/db/migrations/
-->env.py
-->script.py.mako
-->versions/
(este esta por fuera)
alembic.ini

** HACER LAS SIGUIENTES CONFIGURACIONES UNA VEZ SE OBSERVE ESE ARCHIVO **

sqlalchemy.url = driver://user:pass@localhost/dbname 

** CAMBIAR POR **

sqlalchemy.url =

** CONFIGURACION DE app/db/migrations/env.py **

IMPORTS

from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
from app.core.config import settings
from app.db.base import Base 
from app.models import * 

** DESPUES DE config = context.config (line 15) **
** AGREGAR **

config.set_main_option(
    "sqlalchemy.url",
    settings.database_url
)

** AJUSTAR EL METADATA DE ENV.py

target_metadata = None 
** CAMBIAR POR **
target_metadata = None

** EJECUTAR **



** AL REALIZAR ESO EJECUTAMOS EL UVICORN**

POR LO GENERAL SE EJECUTA EN LA SIGUIENTE URL => http://127.0.0.1:8000


** PARA SALIR UNICAMENTE HACER (CTRL + C) Y ESPERAR A QUE RETORNE A ENTORNO VIRTUAL QUE SE ESTA TRABAJANDO **


** SE ENCONTRARA UN ERROR DE Favicon, pero no afecta el trabajo **

** CREA LA BD EN Postgree desde consola **
iniciar la sesion -->"C:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -p 5432 -U postgres
La ruta puede cambiar cuidado --> "C:\Program Files\PostgreSQL\18\bin\psql.exe"  debes ejecutar sobre la ruta donde tengas en psql.exe
CREAR LA BD --> CREATE DATABASE technical_test;

PARA ASEGURAR SU FUNCIONAMIENTO --> \l 

** PARA PROBAR EL ALEMBIC

1. alembic revision -m "init"
2. alembic upgrade head

ALGUNOS PROBLEMAS SON EL ENCONDING DEBE ESTAR EN UFT-8
OTROS CON EL USER Y PASSWORD QUE SE AROJA EN EL .env --> Manejarlos con el usuario creado en postgree

SI TODO ESTA BIEN DEBE APARECER 

INFO [alembic.runtime.migration] Context impl PostgresqlImpl. 
INFO [alembic.runtime.migration] Will assume transactional DDL. 
INFO [alembic.runtime.migration] Running upgrade -> 6158fc7f1572, init INFO [alembic.runtime.migration] Running upgrade 6158fc7f1572 -> f783b0f25755, init


** LOS MODELOS **
PRIMERO EMPIEZA POR app/models/user.py

from sqlalchemy import String, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )


---------------------------------------------------------------------------

MODULO DE SEGURIDAD app/core/security.py

from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

----------------------------------------------------------------------------

tienes un archivo llamado prueba para probar su funcionamiento, es la linea que tiene comentarios desativalos y comenta lo que esta probado

"""from app.core.security import hash_password, verify_password

password = "admin123"

hashed = hash_password(password)

print("Password original:", password)
print("Password hasheado:", hashed)

print("Verificación correcta:", verify_password("admin123", hashed))
print("Verificación incorrecta:", verify_password("otra", hashed))"""

-----------------------------------------------------------------------------*

SI FUNCIONA NOS DEBE DAR EL USUARIO Y LA CONTRASEÑA Y UNA BREVE CONFIRMACION


------------------------------------------------------------------------------
reajustes en app/models/user.py

from sqlalchemy import Column, Integer, String, Boolean
from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
-------------------------------------------------------------------------------

ESTO SE HACE CON EL FIN DE LA AUTENTICACION 


-------------------------------------------------------------------------------

VERIFICAR LAS VARIBALES DE ENTORNO DE USUARIO INICIAL EN .env

FIRST_SUPERUSER_EMAIL=admin@example.com
FIRST_SUPERUSER_PASSWORD=admin123

--------------------------------------------------------------------------------

CREAR app/core/startup.py

from sqlalchemy.orm import Session
from app.models.user import User
from app.core.security import hash_password
from app.core.config import settings

def create_initial_user(db: Session):
    user = db.query(User).filter(
        User.email == settings.FIRST_SUPERUSER_EMAIL
    ).first()

    if not user:
        user = User(
            email=settings.FIRST_SUPERUSER_EMAIL,
            hashed_password=hash_password(settings.FIRST_SUPERUSER_PASSWORD),
            is_active=True,
            is_superuser=True,
        )
        db.add(user)
        db.commit()
        print("Usuario inicial creado")
    else:
        print("Usuario inicial ya existe")

------------------------------------------------------------------------------
CREAMOS MAIN.py

from fastapi import FastAPI
from app.db.databse import SessionLocal
from app.core.startup import create_initial_user

app = FastAPI()

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        create_initial_user(db)
    finally:
        db.close()

----------------------------------------------------------------------------------
CREAR archivo app/models/__init__.py
from app.models.user import User
_--------------------------------------------------------------------------------

REVISAR LOS IMPORTS DE env.py

from app.db.base import Base
from app.models import *
---------------------------------------------------------------------------------

PROBAMOS 

2. alembic upgrade head
---------------------------------------------------------------------------------

editar el config.py para las nuevas varibles de entorno 

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    DB_HOST: str = os.getenv("DB_HOST")
    DB_PORT: int = int(os.getenv("DB_PORT"))
    DB_NAME: str = os.getenv("DB_NAME")
    DB_USER: str = os.getenv("DB_USER")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD")

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", 30))

    FIRST_SUPERUSER_EMAIL: str = os.getenv("FIRST_SUPERUSER_EMAIL")
    FIRST_SUPERUSER_PASSWORD: str = os.getenv("FIRST_SUPERUSER_PASSWORD")

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.DB_USER}:"
            f"{self.DB_PASSWORD}@{self.DB_HOST}:"
            f"{self.DB_PORT}/{self.DB_NAME}"
        )


settings = Settings()


-------------------------------------------------------------------------------------

CREAMOS EL app/core/jwt.py --> Con el fin de tener el token

from datetime import datetime, timedelta
from jose import jwt
from app.core.config import settings


def create_access_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=settings.JWT_EXPIRE_MINUTES
    )

    payload = {
        "sub": subject,
        "exp": expire
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return token

--------------------------------------------------------------------------

PARA PROBAR pega esto en prueba.py

from app.core.jwt import create_access_token
print(create_access_token("admin@local.com"))


---------------------------------------------------------------------

EDITAR STRATUP.PY
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
---------------------------------------------------
LLAMAR AL arrancar el FastAPI (MAIN)

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

-----------------------------------------
---------------------------------------a
CREAMOS app/api/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.core.security import verify_password
from app.core.jwt import create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(
        User.email == form_data.username
    ).first()

    if not user or not verify_password(
        form_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    access_token = create_access_token(user.email)

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

---------------------------------------_
Se incluye en main.py

Al final --> app.include_router(auth_router)

Asi debe quedar main.py hasta ahora

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

-----------------------------------------------------
EDITA app.db.database.py

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


----------------------------------------------------------------------------------------------------------

EJECUTA --> uvicorn app.main:app --reload

--------------------------------------------
añadir modelos que cubre las task
app/models/task.py

import enum

from sqlalchemy import Column, Integer, String, Enum, ForeignKey
from sqlalchemy.orm import relationship

from app.db.base import Base


class TaskStatus(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    done = "done"


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String(255), nullable=False)
    description = Column(String(500), nullable=True)

    status = Column(
        Enum(TaskStatus, name="task_status"),
        nullable=False,
        default=TaskStatus.pending,
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", backref="tasks")

CREAMOS LA TABLA PARA GENERAR LA MIGRACION
alembic revision --autogenerate -m "create tasks table"

despues probamos alembic upgrade head
para verificar si la tabla esta bien creada 
mensaje asi => Running upgrade <prev> -> 7fb5f2775758, create tasks table

CREAMOS la carpeta schemas y dentro de ella el archivo task.py

from pydantic import BaseModel
from typing import Optional
from app.models.task import TaskStatus


class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: TaskStatus = TaskStatus.pending


class TaskCreate(TaskBase):
    pass


class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TaskStatus] = None


class TaskResponse(TaskBase):
    id: int

    class Config:
        from_attributes = True

EDITAMOS EL app/api/task.py

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List
from jose import JWTError, jwt

from app.db.database import get_db
from app.models.task import Task
from app.schemas.task import TaskCreate, TaskUpdate, TaskResponse
from app.models.user import User
from app.core.config import settings

router = APIRouter(
    prefix="/tasks",
    tags=["tasks"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ======================================================
# Obtener usuario actual desde JWT
# ======================================================
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    return user


# ======================================================
# Crear task
# ======================================================
@router.post("/", response_model=TaskResponse)
def create_task(
    task_in: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = Task(
        title=task_in.title,
        description=task_in.description,
        status=task_in.status,
        user_id=current_user.id,
    )

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


# ======================================================
# Listar tasks con PAGINACIÓN
# ======================================================
@router.get("/", response_model=List[TaskResponse])
def list_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Task)
        .filter(Task.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


# ======================================================
#  Actualizar task
# ======================================================
@router.put("/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    task_in: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = (
        db.query(Task)
        .filter(
            Task.id == task_id,
            Task.user_id == current_user.id,
        )
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task no encontrada",
        )

    if task_in.title is not None:
        task.title = task_in.title
    if task_in.description is not None:
        task.description = task_in.description
    if task_in.status is not None:
        task.status = task_in.status

    db.commit()
    db.refresh(task)
    return task


# ======================================================
#  Eliminar task
# ======================================================
@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = (
        db.query(Task)
        .filter(
            Task.id == task_id,
            Task.user_id == current_user.id,
        )
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task no encontrada",
        )

    db.delete(task)
    db.commit()

------------------------------
Registramos en app/main

debe verse asi:

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

-----------------------------------
cerrar el uvicorn (CTRL + C)
Ejecutar nuevamente uvicorn app.main:app --reload
En caso de que no se vean los cambios

----------------------------------------

PARA LAS PAGINACIONES 
modificar en app/api/task.py o asegurar que se vea asi
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List
from jose import JWTError, jwt

from app.db.database import get_db
from app.models.task import Task
from app.schemas.task import TaskCreate, TaskUpdate, TaskResponse
from app.models.user import User
from app.core.config import settings

router = APIRouter(
    prefix="/tasks",
    tags=["tasks"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ======================================================
# Obtener usuario actual desde JWT
# ======================================================
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    return user


# ======================================================
# Crear task
# ======================================================
@router.post("/", response_model=TaskResponse)
def create_task(
    task_in: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = Task(
        title=task_in.title,
        description=task_in.description,
        status=task_in.status,
        user_id=current_user.id,
    )

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


# ======================================================
# Listar tasks con PAGINACIÓN
# ======================================================
@router.get("/", response_model=List[TaskResponse])
def list_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Task)
        .filter(Task.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


# ======================================================
#  Actualizar task
# ======================================================
@router.put("/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    task_in: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = (
        db.query(Task)
        .filter(
            Task.id == task_id,
            Task.user_id == current_user.id,
        )
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task no encontrada",
        )

    if task_in.title is not None:
        task.title = task_in.title
    if task_in.description is not None:
        task.description = task_in.description
    if task_in.status is not None:
        task.status = task_in.status

    db.commit()
    db.refresh(task)
    return task


# ======================================================
# 🗑️ Eliminar task
# ======================================================
@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = (
        db.query(Task)
        .filter(
            Task.id == task_id,
            Task.user_id == current_user.id,
        )
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task no encontrada",
        )

    db.delete(task)
    db.commit()

** PARA DOCKER SE DEBEN CREAR EN LA RAIZ DE PROYECTO LO SIGUIENTE ***

Dockerfile
docker-compose.yml

QUE SON EL compose y el dockerfile que hace el tipo de puente para el funcionamiento

Causa finales 
el startup debe estar asi ajustado 

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


LOS ARCHIVOS DE DOCKER SON LOS QUE ESTAN

Y PARA EJECUTARLOS PODEMOS HACER

docker compose down -v
docker compose build --no-cache
docker compose up


para reconstruir en caso que presentemos alguna error

ver en http://localhost:8000/docs

























