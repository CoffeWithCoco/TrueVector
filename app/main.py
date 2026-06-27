import os
import secrets
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .auth import authenticate_user, create_default_user
from .database import Base, SessionLocal, engine, get_db
from .models import Campaign, User
from .routes import settings as settings_router
from .routes import campaigns as campaigns_router
from .routes import tasks as tasks_router
from .routes import reports as reports_router

load_dotenv()

Base.metadata.create_all(bind=engine)

# Migrate existing DBs that predate later columns
def _migrate_columns():
    import sqlite3, os
    db_path = os.getenv("DATABASE_URL", "sqlite:///./data/smtp_validator.db")
    db_path = db_path.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return
    additions = {
        "config": [
            ("imap_host", "TEXT"),
            ("imap_port", "INTEGER DEFAULT 993"),
            ("imap_user", "TEXT"),
            ("imap_pass", "TEXT"),
            ("reader_backend", "TEXT DEFAULT 'imap'"),
            ("ms_tenant_id", "TEXT"),
            ("ms_client_id", "TEXT"),
            ("ms_client_secret", "TEXT"),
            ("google_sa_json", "TEXT"),
            ("web_base_url", "TEXT"),
            ("cloud_payload_url", "TEXT"),
            ("send_interval", "INTEGER DEFAULT 90"),
            ("send_jitter", "INTEGER DEFAULT 30"),
            ("canaries_enabled", "INTEGER DEFAULT 1"),
            ("canary_every", "INTEGER DEFAULT 7"),
        ],
        "campaigns": [
            ("carrier_status", "TEXT"),
        ],
        "results": [
            ("carrier_suspect", "INTEGER DEFAULT 0"),
        ],
    }
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for table, cols in additions.items():
        existing = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue  # table doesn't exist yet (fresh DB created by create_all)
        for col, definition in cols:
            if col not in existing:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")
    conn.commit()
    conn.close()

_migrate_columns()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        create_default_user(db)
        # Any campaign still "running" at boot is orphaned — its worker thread did
        # not survive the restart. Mark it as failed so it doesn't hang forever.
        orphaned = db.query(Campaign).filter(Campaign.status == "running").all()
        for c in orphaned:
            c.status = "error"
        if orphaned:
            db.commit()
            print(f"[init] {len(orphaned)} orphaned campaign(s) marked as error", flush=True)
    finally:
        db.close()
    yield


app = FastAPI(title="TrueVector — Email Attack Surface Validator", lifespan=lifespan)


def _get_secret_key() -> str:
    """Use SECRET_KEY from env if set; otherwise generate one and persist it
    in data/ so signed sessions survive restarts within the same deploy."""
    key = os.getenv("SECRET_KEY")
    if key:
        return key
    key_path = os.path.join("data", "secret_key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_urlsafe(48)
    os.makedirs("data", exist_ok=True)
    with open(key_path, "w", encoding="utf-8") as fh:
        fh.write(key)
    print("[init] SECRET_KEY generated and persisted to data/secret_key", flush=True)
    return key


SECRET_KEY = _get_secret_key()
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=os.getenv("HTTPS_ONLY", "").lower() in ("1", "true", "yes"),
)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

app.include_router(settings_router.router)
app.include_router(campaigns_router.router)
app.include_router(tasks_router.router)
app.include_router(reports_router.router)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = current_user(request, db)
    if not user:
        raise _redirect_to_login()
    return user


def _redirect_to_login():
    return RedirectResponse("/login", status_code=302)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401,
        )
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return _redirect_to_login()

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return _redirect_to_login()

    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()

    total = len(campaigns)
    running = sum(1 for c in campaigns if c.status == "running")
    done = [c for c in campaigns if c.status == "done" and c.score is not None]
    avg_score = round(sum(c.score for c in done) / len(done), 1) if done else None

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "campaigns": campaigns,
            "active_page": "dashboard",
            "stats": {
                "total": total,
                "running": running,
                "avg_score": avg_score,
            },
        },
    )
