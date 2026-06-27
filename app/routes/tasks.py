"""
Tasks section — inspect each technique's email content before running campaigns.
"""

import email as email_lib
import html as html_lib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..techniques.registry import load_all

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _auth(request: Request, db: Session) -> User | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return db.query(User).filter(User.id == uid).first()


def _extract_content(technique):
    """Build a sample message and extract every piece of useful content."""
    msg = technique.build_message()

    html_parts: list[str] = []
    plain_parts: list[str] = []
    attachments: list[dict] = []

    for part in msg.walk():
        ct = part.get_content_type()
        disposition = part.get("Content-Disposition", "")

        if "attachment" in disposition.lower():
            fname = part.get_filename() or "unnamed"
            raw = part.get_payload(decode=True) or b""
            try:
                preview = raw.decode("utf-8", errors="replace")[:2000]
                is_text = True
            except Exception:
                preview = repr(raw[:200])
                is_text = False
            attachments.append({
                "filename": fname,
                "content_type": ct,
                "size": len(raw),
                "preview": preview,
                "is_text": is_text,
            })
            continue

        if ct == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                html_parts.append(payload.decode("utf-8", errors="replace"))

        elif ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                plain_parts.append(payload.decode("utf-8", errors="replace"))

    # Headers that will actually be on the sent email
    sample_headers = {
        "Subject": msg.get("Subject", technique.meta.name),
        "From": f"Security Validator <probe@your-domain.com>",
        "X-Validator-ID": f"{technique.meta.id}-xxxxxxxx",
        "MIME-Version": "1.0",
    }
    for k, v in msg.items():
        if k.lower() not in ("subject", "from", "to"):
            sample_headers[k] = v

    return {
        "html": "\n\n---\n\n".join(html_parts) if html_parts else None,
        "plain": "\n\n---\n\n".join(plain_parts) if plain_parts else None,
        "attachments": attachments,
        "headers": sample_headers,
    }


@router.get("/tasks", response_class=HTMLResponse)
async def tasks_list(request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return _redir()
    return templates.TemplateResponse("tasks.html", {
        "request": request, "user": user,
        "techniques": load_all(),
        "active_page": "tasks",
    })


@router.get("/tasks/{technique_id}", response_class=HTMLResponse)
async def task_detail(technique_id: str, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return _redir()

    all_tech = {t.meta.id: t for t in load_all()}
    technique = all_tech.get(technique_id.upper())
    if not technique:
        return _redir("/tasks")

    content = _extract_content(technique)

    # Escape HTML source for display in <pre>
    html_escaped = html_lib.escape(content["html"]) if content["html"] else None

    return templates.TemplateResponse("task_detail.html", {
        "request": request, "user": user,
        "technique": technique,
        "content": content,
        "html_escaped": html_escaped,
        "active_page": "tasks",
    })


def _redir(path="/login"):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(path, status_code=302)
