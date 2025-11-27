# models/user_models.py
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr

class UserProfile(BaseModel):
    full_name: str
    phone: Optional[str] = None
    department: Optional[str] = None
    avatar: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str
    profile: UserProfile

class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    role: str
    profile: UserProfile
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    profile: Optional[UserProfile] = None
    is_active: Optional[bool] = None