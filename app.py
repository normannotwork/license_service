import os
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, HTTPException
from fastapi.responses import RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool
import uvicorn
from dotenv import load_dotenv

from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship, joinedload

# ================== CONFIG ==================
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_URL = f"sqlite:///{os.path.join(DATA_DIR, 'licenses.db')}"
LICENSE_GENERATOR_BIN = os.path.join(BASE_DIR, "Prog-license-generator")

SECRET_KEY = os.getenv("APP_SECRET_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if not SECRET_KEY or not ADMIN_PASSWORD:
    raise RuntimeError("Set APP_SECRET_KEY and ADMIN_PASSWORD in .env")

# ================== DB ==================
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    first_name = Column(String)
    last_name = Column(String)

    logs = relationship("LicenseLog", back_populates="user", cascade="all, delete-orphan")


class LicenseLog(Base):
    __tablename__ = "license_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)
    expire_date = Column(String)

    user = relationship("User", back_populates="logs")


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(String)


Base.metadata.create_all(bind=engine)

# ================== INIT SETTINGS ==================
def init_settings():
    db = SessionLocal()
    try:
        if not db.query(Setting).filter_by(key="duration_type").first():
            db.add_all([
                Setting(key="duration_type", value="perpetual"),
                Setting(key="custom_date", value="")
            ])
            db.commit()
    finally:
        db.close()

init_settings()

# ================== APP ==================
app = FastAPI(title="License Generator")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    https_only=False,  # поставь True на проде с HTTPS
)

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ================== DEPENDENCIES ==================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401)

    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=401)

    return user


# ================== UTILS ==================
def run_generator(serial_path: str, license_path: str, target_date: str):
    """Безопасный запуск бинарника"""
    try:
        result = subprocess.run(
            [LICENSE_GENERATOR_BIN, serial_path, license_path, target_date],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result
    except subprocess.TimeoutExpired:
        raise HTTPException(500, "Generator timeout")


def calculate_target_date(db: Session) -> str:
    dur_type = db.query(Setting).filter_by(key="duration_type").first().value

    if dur_type == "perpetual":
        return "never"

    if dur_type == "1_month":
        return (datetime.now() + timedelta(days=30)).strftime("%d.%m.%Y")

    if dur_type == "1_year":
        return (datetime.now() + timedelta(days=365)).strftime("%d.%m.%Y")

    if dur_type == "custom":
        custom = db.query(Setting).filter_by(key="custom_date").first().value
        if not custom:
            raise HTTPException(500, "Custom date not set")

        dt = datetime.strptime(custom, "%Y-%m-%d")
        return dt.strftime("%d.%m.%Y")

    raise HTTPException(500, "Invalid settings")


# ================== ROUTES ==================
@app.get("/")
def root():
    return RedirectResponse("/generator")


# ---------- AUTH ----------
@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    db: Session = Depends(get_db)
):
    email = email.strip().lower()

    user = db.query(User).filter_by(email=email).first()
    if not user:
        user = User(email=email, first_name=first_name, last_name=last_name)
        db.add(user)
        db.commit()
        db.refresh(user)

    request.session["user_id"] = user.id
    return RedirectResponse("/generator", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# ---------- GENERATOR ----------
@app.get("/generator")
def generator_page(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    dur_type = db.query(Setting).filter_by(key="duration_type").first().value

    text_map = {
        "perpetual": "Бессрочная лицензия",
        "1_month": "1 месяц",
        "1_year": "1 год",
        "custom": "Пользовательская дата"
    }

    return templates.TemplateResponse("generator.html", {
        "request": request,
        "user": user,
        "duration_text": text_map.get(dur_type, "Unknown")
    })


@app.post("/api/generate")
async def generate(
    serial_file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not serial_file.filename.endswith(".txt"):
        raise HTTPException(400, "Only .txt allowed")

    if not os.path.exists(LICENSE_GENERATOR_BIN):
        raise HTTPException(500, "Generator not found")

    target_date = calculate_target_date(db)

    temp_dir = tempfile.mkdtemp()

    try:
        serial_path = os.path.join(temp_dir, "serial.txt")
        license_path = os.path.join(temp_dir, "license.txt")

        with open(serial_path, "wb") as f:
            f.write(await serial_file.read())

        result = await run_in_threadpool(run_generator, serial_path, license_path, target_date)

        if result.returncode != 0:
            raise HTTPException(500, result.stderr)

        if not os.path.exists(license_path):
            raise HTTPException(500, "License file not created")

        with open(license_path, "rb") as f:
            data = f.read()

        db.add(LicenseLog(user_id=user.id, expire_date=target_date))
        db.commit()

        return Response(
            content=data,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=license.txt"}
        )

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ---------- ADMIN ----------
@app.get("/admin")
def admin_page(request: Request, db: Session = Depends(get_db)):
    if not request.session.get("is_admin"):
        return RedirectResponse("/admin/login")

    logs = db.query(LicenseLog).options(joinedload(LicenseLog.user)).all()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "logs": logs
    })


@app.post("/admin/login")
def admin_login(request: Request, password: str = Form(...)):
    if password != ADMIN_PASSWORD:
        return JSONResponse({"error": "Wrong password"}, status_code=401)

    request.session["is_admin"] = True
    return RedirectResponse("/admin", status_code=303)


# ================== MAIN ==================
if __name__ == "__main__":
    if os.path.exists(LICENSE_GENERATOR_BIN):
        os.chmod(LICENSE_GENERATOR_BIN, 0o755)

    uvicorn.run(app, host="0.0.0.0", port=8010)