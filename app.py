# Import necessary modules and packages
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, select, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, field_validator
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

DATABASE_URL = "sqlite+aiosqlite:///./test.db"

Base = declarative_base()
engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=AsyncSession
)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, modify this as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open("static/index.html") as f:
        return HTMLResponse(content=f.read(), status_code=200)


# Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    user_contract = relationship(
        "UserContract", back_populates="user", uselist=False, lazy="selectin"
    )


class Contract(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, unique=True, index=True)


class UserContract(Base):
    __tablename__ = "user_contracts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    contract_id = Column(Integer, ForeignKey("contracts.id"))
    contract_time = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="user_contract", lazy="selectin")
    contract = relationship("Contract", lazy="selectin")


# Schemas
class UserCreate(BaseModel):
    name: str
    password: str


class ContractCreate(BaseModel):
    category: str
    user_id: int

    @field_validator("category")
    def category_must_be_valid(cls, v):
        if v not in ["basic", "normal", "premium"]:
            raise ValueError("Category must be one of: basic, normal, premium")
        return v


class ContractUpdate(BaseModel):
    category: Optional[str] = None

    @field_validator("category")
    def category_must_be_valid(cls, v):
        if v and v not in ["basic", "normal", "premium"]:
            raise ValueError("Category must be one of: basic, normal, premium")
        return v


class AskAdmin(BaseModel):
    action: str
    username: str
    category: Optional[str] = None


class ConfirmAction(BaseModel):
    action: str
    username: str
    category: Optional[str] = None
    confirmed: bool


# Dependencies
async def get_db():
    async with SessionLocal() as session:
        yield session


async def get_user_by_name(db: AsyncSession, name: str):
    result = await db.execute(select(User).filter(User.name == name))
    return result.scalar()


async def get_user_by_id(db: AsyncSession, user_id: int):
    result = await db.execute(select(User).filter(User.id == user_id))
    return result.scalar()


async def get_current_user(
    db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)
):
    user = await get_user_by_name(db, token)
    if user is None:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )
    return user


async def get_current_admin_user(
    db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)
):
    user = await get_current_user(db, token)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    return user


# Password Hashing
def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


clients = []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Process incoming WebSocket messages if needed
    except WebSocketDisconnect:
        clients.remove(websocket)


async def notify_clients(message: dict):
    for client in clients:
        await client.send_json(message)


# Routes
@app.post("/register/")
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_name(db, user.name)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(name=user.name, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@app.post("/token/")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_name(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return {"access_token": user.name, "token_type": "bearer"}


@app.post("/contracts/")
async def create_contract(
    contract: ContractCreate,
    db: AsyncSession = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user),
):
    user = await get_user_by_id(db, contract.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_contract = await db.execute(
        select(UserContract).filter(UserContract.user_id == contract.user_id)
    )
    if existing_contract.scalar():
        raise HTTPException(status_code=400, detail="User already has a contract")

    contract_category = await db.execute(
        select(Contract).filter_by(category=contract.category)
    )
    contract_record = contract_category.scalar()
    if not contract_record:
        raise HTTPException(status_code=404, detail="Contract category not found")

    new_user_contract = UserContract(
        user_id=contract.user_id,
        contract_id=contract_record.id,
        contract_time=datetime.utcnow(),
    )
    db.add(new_user_contract)
    await db.commit()
    await db.refresh(new_user_contract)

    return {
        "id": new_user_contract.id,
        "category": contract_record.category,
        "contract_time": new_user_contract.contract_time,
        "user_id": new_user_contract.user_id,
    }


@app.put("/contracts/{contract_id}/")
async def update_contract(
    contract_id: int,
    contract: ContractUpdate,
    db: AsyncSession = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user),
):
    db_contract = await db.get(UserContract, contract_id)
    if not db_contract:
        raise HTTPException(status_code=404, detail="Contract not found")
    if db_contract.user_id != current_admin_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to update this contract"
        )
    for key, value in contract.dict(exclude_unset=True).items():
        setattr(db_contract, key, value)
    await db.commit()
    await db.refresh(db_contract)
    return db_contract


@app.delete("/contracts/{contract_id}/")
async def delete_contract(
    contract_id: int,
    db: AsyncSession = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user),
):
    db_contract = await db.get(UserContract, contract_id)
    if not db_contract:
        raise HTTPException(status_code=404, detail="Contract not found")
    if db_contract.user_id != current_admin_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this contract"
        )
    db_contract.contract_time = datetime.utcnow() + timedelta(days=90)
    await db.commit()

    return {"detail": "Contract will be cancelled in 3 months"}


@app.post("/ask_admin/")
async def ask_admin(request: AskAdmin):
    message = request.dict()
    await notify_clients(message)
    return {"message": "Admin approval requested"}


import asyncio


@app.post("/confirm_action/")
async def confirm_action(request: ConfirmAction, db: AsyncSession = Depends(get_db)):
    # Simulate waiting for admin confirmation status
    while True:
        if not request.confirmed:
            await asyncio.sleep(1)  # Sleep to simulate waiting for actual admin input
            continue

        if request.action == "create":
            user = await get_user_by_name(db, request.username)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            contract_category = await db.execute(
                select(Contract).filter_by(category=request.category)
            )
            contract_record = contract_category.scalar()
            if not contract_record:
                raise HTTPException(
                    status_code=404, detail="Contract category not found"
                )

            new_user_contract = UserContract(
                user_id=user.id,
                contract_id=contract_record.id,
                contract_time=datetime.utcnow(),
            )
            db.add(new_user_contract)
            await db.commit()
            await db.refresh(new_user_contract)

            return {
                "message": "Contract created",
                "id": new_user_contract.id,
                "category": contract_record.category,
                "contract_time": new_user_contract.contract_time,
                "user_id": new_user_contract.user_id,
            }
        elif request.action == "delete":
            user = await get_user_by_name(db, request.username)
            if not user or not user.user_contract:
                raise HTTPException(
                    status_code=404, detail="User or contract not found"
                )

            db_contract = user.user_contract
            db_contract.contract_time = datetime.utcnow() + timedelta(days=90)
            await db.commit()

            return {"message": "Contract will be cancelled in 3 months"}

        return {"message": "Action not recognized"}


@app.get("/users/")
async def get_all_users(
    db: AsyncSession = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user),
):
    result = await db.execute(
        select(User).options(
            selectinload(User.user_contract).selectinload(UserContract.contract)
        )
    )
    users = result.scalars().all()
    return users


@app.get("/users/{username}")
async def get_user_by_username(username: str, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_name(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/contracts/user/{username}")
async def get_contract_by_username(username: str, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_name(db, username)
    if not user or not user.user_contract:
        return JSONResponse(content={"message": "No contract"}, status_code=404)
    return {
        "id": user.user_contract.id,
        "category": user.user_contract.contract.category,
        "contract_time": user.user_contract.contract_time,
        "user_id": user.id,
    }


# Use this endpoint to send the status of admin confirmation
@app.get("/check_confirmation/{username}")
async def check_confirmation(username: str, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_name(db, username)
    if user and user.user_contract:
        contract = user.user_contract
        return {
            "message": "Contract created",
            "id": contract.id,
            "category": contract.contract.category,
            "contract_time": contract.contract_time,
            "user_id": contract.user_id,
        }
    return {"message": "Waiting for admin confirmation"}


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as db:
        categories = ["basic", "normal", "premium"]
        for category in categories:
            existing_contract = await db.execute(
                select(Contract).filter_by(category=category)
            )
            if not existing_contract.scalar():
                new_contract = Contract(category=category)
                db.add(new_contract)
        await db.commit()

        admin1 = await get_user_by_name(db, "admin1")
        if not admin1:
            hashed_password = get_password_hash("admin1password")
            admin1 = User(name="admin1", hashed_password=hashed_password, is_admin=True)
            db.add(admin1)

        admin2 = await get_user_by_name(db, "admin2")
        if not admin2:
            hashed_password = get_password_hash("admin2password")
            admin2 = User(name="admin2", hashed_password=hashed_password, is_admin=True)
            db.add(admin2)

        await db.commit()


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, log_level="info")
