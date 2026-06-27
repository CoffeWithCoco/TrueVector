import json

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Campaign, User

router = APIRouter()


def _auth(request: Request, db: Session) -> User | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return db.query(User).filter(User.id == uid).first()


@router.get("/reports", response_class=HTMLResponse)
async def reports_list(request: Request, db: Session = Depends(get_db)):
    from ..main import templates
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    campaigns = (
        db.query(Campaign)
        .filter(Campaign.status == "done")
        .order_by(Campaign.finished_at.desc())
        .all()
    )

    # Augment each campaign with parsed technique count for template
    report_items = []
    for c in campaigns:
        try:
            tech_count = len(json.loads(c.selected_techniques or "[]"))
        except Exception:
            tech_count = 0
        report_items.append({"campaign": c, "tech_count": tech_count})

    return templates.TemplateResponse(
        "reports.html",
        {
            "request": request,
            "user": user,
            "report_items": report_items,
            "active_page": "reports",
        },
    )


@router.get("/reports/techniques", response_class=HTMLResponse)
async def techniques_reference(request: Request, db: Session = Depends(get_db)):
    """In-app reference of every technique: why it is sent and the exact payload
    it carries (same content as the offline PDF dossier, fully English)."""
    from ..main import templates
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    from ..techniques.reference import build_reference
    techniques = build_reference()
    return templates.TemplateResponse(
        "techniques_reference.html",
        {
            "request": request,
            "user": user,
            "techniques": techniques,
            "active_page": "reports",
        },
    )
