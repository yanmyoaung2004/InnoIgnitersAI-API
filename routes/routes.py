from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from models.schemas import SignupIn, LoginIn, TokenOut, UserOut, RefreshIn, OAuthLoginIn
from models.models import User
from utils.utils import hash_password, verify_password, create_token_pair, decode_token, generate_random_password
from database.deps import get_db

router = APIRouter(prefix="/auth", tags=[""])

@router.post("/signup", response_model=UserOut)
def signup(body: SignupIn, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == body.email))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    u = User(email=body.email, password_hash=hash_password(body.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    return UserOut(id=u.id, email=u.email)

@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return create_token_pair(user.email)

@router.post("/oauth", response_model=TokenOut)
def login(body: OAuthLoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email))
    if not user:
        random_password = generate_random_password()
        hashed_password = hash_password(random_password)
        user = User(
            email=body.email,
            password_hash=hashed_password
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return create_token_pair(user.email)

@router.post("/refresh", response_model=TokenOut)
def refresh_tokens(body: RefreshIn, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Wrong token type")
    email = payload.get("sub")
    user = db.scalar(select(User).where(User.email == email))
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return create_token_pair(email)
