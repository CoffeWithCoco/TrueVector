from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Config, User
from ..core.reader import reader_from_config
from ..core.sender import test_smtp

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _auth(request: Request, db: Session) -> User | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return db.query(User).filter(User.id == uid).first()


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    config = db.query(Config).filter(Config.id == 1).first() or Config()
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "user": user,
        "config": config,
        "active_page": "settings",
        "saved": request.query_params.get("saved"),
    })


@router.post("/settings")
async def settings_save(
    request: Request,
    smtp_host: str = Form(""),
    smtp_port: int = Form(587),
    smtp_user: str = Form(""),
    smtp_pass: str = Form(""),
    from_domain: str = Form(""),
    from_name: str = Form("Security Validator"),
    send_interval: int = Form(90),
    send_jitter: int = Form(30),
    canaries_enabled: bool = Form(False),
    canary_every: int = Form(7),
    target_email: str = Form(""),
    reader_backend: str = Form("imap"),
    imap_host: str = Form(""),
    imap_port: int = Form(993),
    imap_user: str = Form(""),
    imap_pass: str = Form(""),
    ms_tenant_id: str = Form(""),
    ms_client_id: str = Form(""),
    ms_client_secret: str = Form(""),
    google_sa_json: str = Form(""),
    web_base_url: str = Form(""),
    cloud_payload_url: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    config = db.query(Config).filter(Config.id == 1).first()
    if not config:
        config = Config(id=1)
        db.add(config)

    config.smtp_host = smtp_host
    config.smtp_port = smtp_port
    config.smtp_user = smtp_user
    config.from_domain = from_domain
    config.from_name = from_name
    config.send_interval = max(0, send_interval)
    config.send_jitter = max(0, send_jitter)
    config.canaries_enabled = canaries_enabled
    config.canary_every = max(1, canary_every)
    config.target_email = target_email
    config.reader_backend = reader_backend
    config.imap_host = imap_host
    config.imap_port = imap_port
    config.imap_user = imap_user
    config.ms_tenant_id = ms_tenant_id
    config.ms_client_id = ms_client_id
    config.web_base_url = web_base_url
    config.cloud_payload_url = cloud_payload_url

    if smtp_pass:
        config.smtp_pass = smtp_pass
    if imap_pass:
        config.imap_pass = imap_pass
    # Secrets: keep existing value when the field is submitted empty.
    if ms_client_secret:
        config.ms_client_secret = ms_client_secret
    if google_sa_json:
        config.google_sa_json = google_sa_json

    db.commit()
    return RedirectResponse("/settings?saved=1", status_code=302)


@router.post("/settings/test")
async def settings_test(request: Request, db: Session = Depends(get_db)):
    """Test the saved SMTP and mailbox-reader connections without sending anything."""
    user = _auth(request, db)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    config = db.query(Config).filter(Config.id == 1).first()
    if not config:
        return JSONResponse({"error": "No configuration saved yet."}, status_code=400)

    smtp_ok, smtp_msg = test_smtp(config)

    backend = (config.reader_backend or "imap").lower()
    backend_label = {"imap": "IMAP", "microsoft": "Microsoft Graph", "google": "Gmail API"}.get(backend, backend)
    try:
        reader_ok, reader_msg = reader_from_config(config).test_connection()
    except Exception as exc:
        reader_ok, reader_msg = False, f"Reader error: {exc}"

    return JSONResponse({
        "smtp": {"ok": smtp_ok, "message": smtp_msg},
        "reader": {"ok": reader_ok, "message": reader_msg, "backend": backend_label},
    })
