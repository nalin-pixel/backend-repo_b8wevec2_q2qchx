"""
Database Schemas for PFA

Define MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in the database.
Collection name is lowercase of the class name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import date

# Auth/User
class User(BaseModel):
    email: EmailStr = Field(..., description="User email")
    hashed_password: str = Field(..., description="BCrypt hashed password")
    full_name: Optional[str] = Field(None, description="Full name")
    locale: str = Field("he", description="UI language, default Hebrew")

# Documents uploaded by users
class Document(BaseModel):
    user_id: str = Field(..., description="Owner user id")
    filename: str = Field(..., description="Original file name")
    content_type: str = Field(..., description="MIME type")
    size_bytes: int = Field(..., ge=0)
    storage_path: str = Field(..., description="Path in storage")
    doc_type: Literal["paystub","bank","credit","loan"] = Field(..., description="Detected document type")
    month: int = Field(..., ge=1, le=12)
    year: int = Field(..., ge=1900, le=2100)
    status: Literal["uploaded","processed","failed"] = Field("uploaded")

# Extracted transactions (normalized)
class Transaction(BaseModel):
    user_id: str
    doc_id: str
    date: date
    description: str
    amount: float = Field(..., description="Positive for income, negative for expense")
    category: str = Field("Uncategorized")
    source: Literal["bank","credit","paystub","manual"] = "manual"
    month: int
    year: int

# Sharing links with permissions
class ShareLink(BaseModel):
    user_id: str
    token: str
    scope: Literal["dashboard","report"] = "dashboard"
    permission: Literal["view","edit"] = "view"
    expires_at: Optional[str] = None
    approved: bool = False

# Simple categories configuration
class Category(BaseModel):
    user_id: str
    name: str
    color: Optional[str] = None

# Helper response models
class CashflowSummary(BaseModel):
    month: int
    year: int
    income: float
    expense: float
    net: float
    by_category: List[dict]
