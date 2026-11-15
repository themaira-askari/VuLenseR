import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from database import create_user, get_user_by_email, public_user
from auth_service import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

@router.post("/register")
def register(request: RegisterRequest):
    name = request.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Please enter your full name.")
    if get_user_by_email(request.email):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    try:
        user = create_user(name, request.email, hash_password(request.password), "user")
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            raise HTTPException(status_code=409, detail="An account with this email already exists.")
        raise
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": public_user(user)}

@router.post("/login")
def login(request: LoginRequest):
    user = get_user_by_email(request.email)
    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Your account has been deactivated. Contact the administrator.")
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": public_user(user)}

@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"user": public_user(user)}
