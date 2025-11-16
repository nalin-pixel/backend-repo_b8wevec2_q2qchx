import os
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import User as UserSchema, Document as DocumentSchema, Transaction as TransactionSchema, ShareLink as ShareLinkSchema

# ---------------------------
# Security & Auth Settings
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")  # remove leading slash to avoid FieldInfo.in_ bug


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterPayload(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"email": email})
    if not user:
        raise credentials_exception
    return user


# ---------------------------
# App Init
# ---------------------------
app = FastAPI(title="Personal Financial Analyzer (PFA)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------
# Basic Routes
# ---------------------------
@app.get("/")
def root():
    return {"name": "PFA API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
        else:
            response["database"] = "❌ db not initialized"
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:60]}"
    return response


# ---------------------------
# Auth Endpoints
# ---------------------------
@app.post("/auth/register", response_model=Token)
def register(payload: RegisterPayload):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(payload.password)
    user_doc = UserSchema(email=payload.email, hashed_password=hashed, full_name=payload.full_name, locale="he")
    create_document("user", user_doc)
    token = create_access_token({"sub": payload.email})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"sub": user["email"]})
    return Token(access_token=token)


# NEW: Guest access for quick preview without registration
@app.post("/auth/guest", response_model=Token)
def guest_access():
    """
    Create a temporary guest user and return a JWT. Guest users are regular users
    stored in the database with a unique email and a random hashed password.
    """
    from secrets import token_urlsafe

    # Generate a unique guest email
    suffix = token_urlsafe(8)
    email = f"guest-{suffix}@example.com"
    hashed = get_password_hash(token_urlsafe(16))
    user_doc = UserSchema(email=email, hashed_password=hashed, full_name="Guest", locale="he")
    create_document("user", user_doc)

    token = create_access_token({"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return Token(access_token=token)


# ---------------------------
# Documents Upload & Processing
# ---------------------------
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "files/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def naive_transaction_parser(file_path: str, detected_type: str, month: int, year: int):
    """
    Very simple parser:
    - If CSV: expects columns: date, description, amount, category
    - Otherwise: creates a placeholder income/expense to demonstrate flow
    """
    records: List[TransactionSchema] = []
    try:
        if file_path.lower().endswith(".csv"):
            import csv
            with open(file_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        d = row.get("date") or row.get("Date")
                        desc = row.get("description") or row.get("Description") or ""
                        amt = float(row.get("amount") or row.get("Amount") or 0)
                        cat = row.get("category") or row.get("Category") or "Uncategorized"
                        dt = date.fromisoformat(d)
                        records.append({
                            "date": dt,
                            "description": desc,
                            "amount": amt,
                            "category": cat,
                            "source": detected_type if detected_type in ["bank","credit","paystub","manual"] else "manual",
                            "month": month,
                            "year": year,
                        })
                    except Exception:
                        continue
        else:
            # placeholder: one net income for paystub, one expense for others
            if detected_type == "paystub":
                records.append({
                    "date": date(year, month, 1),
                    "description": "Net Income",
                    "amount": 10000.0,
                    "category": "Income",
                    "source": "paystub",
                    "month": month,
                    "year": year,
                })
            else:
                records.append({
                    "date": date(year, month, 2),
                    "description": "General Expense",
                    "amount": -2500.0,
                    "category": "Other",
                    "source": detected_type,
                    "month": month,
                    "year": year,
                })
    except Exception:
        pass
    return records


@app.post("/documents/upload")
async def upload_document(
    doc_type: Literal["paystub","bank","credit","loan"] = Form(...),
    month: int = Form(...),
    year: int = Form(...),
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    if month < 1 or month > 12:
        raise HTTPException(status_code=400, detail="Invalid month")
    if year < 1900 or year > 2100:
        raise HTTPException(status_code=400, detail="Invalid year")

    # Save file
    filename = f"{datetime.now(timezone.utc).timestamp()}_{file.filename}"
    storage_path = os.path.join(UPLOAD_DIR, filename)
    with open(storage_path, "wb") as out:
        content = await file.read()
        out.write(content)

    # Create document record
    doc = DocumentSchema(
        user_id=str(user.get("_id")),
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
        storage_path=storage_path,
        doc_type=doc_type,
        month=month,
        year=year,
        status="uploaded",
    )
    doc_id = create_document("document", doc)

    # Parse transactions (naive demo)
    parsed = naive_transaction_parser(storage_path, doc_type, month, year)
    for rec in parsed:
        tdoc = TransactionSchema(
            user_id=str(user.get("_id")),
            doc_id=doc_id,
            date=rec["date"],
            description=rec["description"],
            amount=rec["amount"],
            category=rec["category"],
            source=rec["source"],
            month=rec["month"],
            year=rec["year"],
        )
        create_document("transaction", tdoc)

    # Mark processed
    db["document"].update_one({"_id": db["document"].find_one({"_id": doc_id})}, {"$set": {"status": "processed"}})

    return {"ok": True, "document_id": doc_id, "transactions_created": len(parsed)}


# ---------------------------
# Transactions & Summary
# ---------------------------
@app.get("/transactions")
def list_transactions(month: Optional[int] = None, year: Optional[int] = None, user=Depends(get_current_user)):
    filt = {"user_id": str(user.get("_id"))}
    if month:
        filt["month"] = month
    if year:
        filt["year"] = year
    docs = get_documents("transaction", filt, limit=None)
    for d in docs:
        d["_id"] = str(d.get("_id"))
        if isinstance(d.get("date"), datetime):
            d["date"] = d["date"].date().isoformat()
        elif isinstance(d.get("date"), date):
            d["date"] = d["date"].isoformat()
    return {"items": docs}


@app.get("/summary")
def summary(month: int, year: int, user=Depends(get_current_user)):
    filt = {"user_id": str(user.get("_id")), "month": month, "year": year}
    txs = get_documents("transaction", filt, limit=None)
    income = sum(t.get("amount", 0) for t in txs if float(t.get("amount", 0)) > 0)
    expense = sum(t.get("amount", 0) for t in txs if float(t.get("amount", 0)) < 0)
    by_cat = {}
    for t in txs:
        cat = t.get("category", "Uncategorized")
        by_cat.setdefault(cat, 0.0)
        by_cat[cat] += float(t.get("amount", 0))
    by_category = [{"category": k, "total": v} for k, v in by_cat.items()]
    return {
        "month": month,
        "year": year,
        "income": round(income, 2),
        "expense": round(abs(expense), 2),
        "net": round(income + expense, 2),
        "by_category": by_category,
    }


# ---------------------------
# Sharing Links
# ---------------------------
from secrets import token_urlsafe


class ShareCreatePayload(BaseModel):
    scope: Literal["dashboard","report"] = "dashboard"
    permission: Literal["view","edit"] = "view"
    expires_minutes: Optional[int] = 60 * 24


@app.post("/share/create")
def share_create(payload: ShareCreatePayload, user=Depends(get_current_user)):
    tok = token_urlsafe(16)
    link = ShareLinkSchema(
        user_id=str(user.get("_id")),
        token=tok,
        scope=payload.scope,
        permission=payload.permission,
        approved=False,
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=payload.expires_minutes or 60*24)).isoformat(),
    )
    create_document("sharelink", link)
    return {"token": tok, "approved": False}


class ShareDecision(BaseModel):
    token: str
    approve: bool


@app.post("/share/approve")
def share_approve(decision: ShareDecision, user=Depends(get_current_user)):
    q = {"user_id": str(user.get("_id")), "token": decision.token}
    found = db["sharelink"].find_one(q)
    if not found:
        raise HTTPException(status_code=404, detail="Share link not found")
    db["sharelink"].update_one(q, {"$set": {"approved": decision.approve}})
    return {"ok": True, "approved": decision.approve}


@app.get("/share/{token}/summary")
def shared_summary(token: str, month: int, year: int):
    link = db["sharelink"].find_one({"token": token})
    if not link or not link.get("approved"):
        raise HTTPException(status_code=403, detail="Link not approved")
    user_id = link.get("user_id")
    txs = get_documents("transaction", {"user_id": user_id, "month": month, "year": year}, limit=None)
    income = sum(t.get("amount", 0) for t in txs if float(t.get("amount", 0)) > 0)
    expense = sum(t.get("amount", 0) for t in txs if float(t.get("amount", 0)) < 0)
    by_cat = {}
    for t in txs:
        cat = t.get("category", "Uncategorized")
        by_cat.setdefault(cat, 0.0)
        by_cat[cat] += float(t.get("amount", 0))
    return {
        "month": month,
        "year": year,
        "income": round(income, 2),
        "expense": round(abs(expense), 2),
        "net": round(income + expense, 2),
        "by_category": [{"category": k, "total": v} for k, v in by_cat.items()],
        "permission": link.get("permission", "view"),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
