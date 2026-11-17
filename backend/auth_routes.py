import base64
import re
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, EmailStr, Field
from database import (create_user, get_user_by_email, public_user, update_user_name,
                      update_user_avatar, update_user_password)
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


# ------------------------------------------------------------------
# PROFILE MANAGEMENT (name, picture, password) - works for user & admin
# ------------------------------------------------------------------
MAX_AVATAR_BYTES = 2 * 1024 * 1024


class ProfileUpdateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


def _detect_image_type(raw: bytes):
    """Check real file signature instead of trusting the filename / content-type."""
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return None


@router.put("/profile")
def update_profile(request: ProfileUpdateRequest, user: dict = Depends(get_current_user)):
    name = request.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Please enter your full name.")
    return {"user": public_user(update_user_name(user["id"], name))}


@router.post("/avatar")
async def upload_avatar(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    raw = await file.read(MAX_AVATAR_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=400, detail="The selected image is empty.")
    if len(raw) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="Image must be 2 MB or smaller.")
    mime = _detect_image_type(raw)
    if not mime:
        raise HTTPException(status_code=415, detail="Please choose a PNG, JPG or WEBP image.")
    data_url = f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
    return {"user": public_user(update_user_avatar(user["id"], data_url))}


@router.delete("/avatar")
def remove_avatar(user: dict = Depends(get_current_user)):
    return {"user": public_user(update_user_avatar(user["id"], None))}


@router.post("/change-password")
def change_password(request: PasswordChangeRequest, user: dict = Depends(get_current_user)):
    if not verify_password(request.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    if request.current_password == request.new_password:
        raise HTTPException(status_code=422, detail="New password must be different from the current one.")
    update_user_password(user["id"], hash_password(request.new_password))
    return {"message": "Password updated successfully."}
