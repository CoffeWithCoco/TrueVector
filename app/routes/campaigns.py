import json
from typing import Annotated, List

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Campaign, Config, User
from ..techniques.registry import load_all

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _auth(request: Request, db: Session) -> User | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return db.query(User).filter(User.id == uid).first()


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("/campaigns", response_class=HTMLResponse)
async def campaigns_list(request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return templates.TemplateResponse("campaigns.html", {
        "request": request, "user": user,
        "campaigns": campaigns, "active_page": "campaigns",
    })


# ── New ───────────────────────────────────────────────────────────────────────

def _locked_techniques(techniques, config) -> dict[str, str]:
    """Map technique_id -> required config field, for techniques whose hosting
    requirement is not configured (they can't run and are disabled in the picker)."""
    return {
        t.meta.id: t.meta.requires
        for t in techniques
        if t.meta.requires and not getattr(config, t.meta.requires, None)
    }


@router.get("/campaigns/new", response_class=HTMLResponse)
async def campaign_new(request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    techniques = load_all()
    config = db.query(Config).filter(Config.id == 1).first()
    return templates.TemplateResponse("campaign_new.html", {
        "request": request, "user": user,
        "active_page": "campaigns",
        "techniques": techniques,
        "locked": _locked_techniques(techniques, config),
        "error": None,
    })


@router.post("/campaigns")
async def campaign_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    techniques: Annotated[List[str], Form()] = [],
    db: Session = Depends(get_db),
):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if not techniques:
        all_tech = load_all()
        config = db.query(Config).filter(Config.id == 1).first()
        return templates.TemplateResponse("campaign_new.html", {
            "request": request, "user": user,
            "active_page": "campaigns",
            "techniques": all_tech,
            "locked": _locked_techniques(all_tech, config),
            "error": "Select at least one technique.",
        }, status_code=422)

    campaign = Campaign(
        name=name,
        description=description or None,
        selected_techniques=json.dumps(techniques),
        status="pending",
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return RedirectResponse(f"/campaigns/{campaign.id}", status_code=302)


# ── Detail ────────────────────────────────────────────────────────────────────

@router.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
async def campaign_detail(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)

    selected = json.loads(campaign.selected_techniques or "[]")
    all_tech  = {t.meta.id: t for t in load_all()}
    chosen    = [all_tech[tid] for tid in selected if tid in all_tech]

    config = db.query(Config).filter(Config.id == 1).first()
    demo_mode = any(
        (r.validator_id or "").startswith("mock-") for r in campaign.results
    )
    from ..core.carrier import split_results
    canaries, tech_results = split_results(campaign.results)
    return templates.TemplateResponse("campaign_detail.html", {
        "request": request, "user": user,
        "campaign": campaign, "chosen_techniques": chosen,
        "tech_results": tech_results, "canaries": canaries,
        "config": config,
        "demo_mode": demo_mode,
        "active_page": "campaigns",
    })


# ── Launch ────────────────────────────────────────────────────────────────────

@router.post("/campaigns/{campaign_id}/launch")
async def campaign_launch(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign or campaign.status not in ("pending", "error"):
        return RedirectResponse(f"/campaigns/{campaign_id}", status_code=302)

    campaign.status = "running"
    db.commit()

    # Run in a daemon thread: the worker does blocking SMTP/IMAP I/O and a long
    # delivery wait, so keeping it off the event loop lets the UI keep refreshing.
    import threading
    from ..core.worker import run_campaign
    threading.Thread(target=run_campaign, args=(campaign_id,), daemon=True).start()

    return RedirectResponse(f"/campaigns/{campaign_id}", status_code=302)


# ── Re-analyze (re-read mailbox without resending) ──────────────────────────────

@router.post("/campaigns/{campaign_id}/reanalyze")
async def campaign_reanalyze(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    # Only meaningful once a run has finished (or errored) — never mid-send.
    if not campaign or campaign.status not in ("done", "error"):
        return RedirectResponse(f"/campaigns/{campaign_id}", status_code=302)
    # Nothing to re-read for a demo campaign (no real mailbox behind it).
    if any((r.validator_id or "").startswith("mock-") for r in campaign.results):
        return RedirectResponse(f"/campaigns/{campaign_id}", status_code=302)

    campaign.status = "running"
    db.commit()

    import threading
    from ..core.worker import reanalyze_campaign
    threading.Thread(target=reanalyze_campaign, args=(campaign_id,), daemon=True).start()

    return RedirectResponse(f"/campaigns/{campaign_id}", status_code=302)


# ── Re-test (clone into a fresh campaign, ready to launch) ──────────────────────

@router.post("/campaigns/{campaign_id}/retest")
async def campaign_retest(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    """Clone an existing campaign (same techniques) into a new 'pending' one so the
    operator can re-test after changing the gateway. Unlike re-read, the new
    campaign SENDS fresh emails — but only once they hit Launch, so nothing is sent
    by accident here."""
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    source = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not source:
        return RedirectResponse("/campaigns", status_code=302)

    clone = Campaign(
        name=f"{source.name} (re-test)",
        description=source.description,
        selected_techniques=source.selected_techniques,
        status="pending",
    )
    db.add(clone)
    db.commit()
    db.refresh(clone)
    return RedirectResponse(f"/campaigns/{clone.id}", status_code=302)


# ── PDF report ────────────────────────────────────────────────────────────────

@router.get("/campaigns/{campaign_id}/report.pdf")
async def campaign_report(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        return RedirectResponse("/campaigns", status_code=302)

    from ..core.reporter import generate_report
    config = db.query(Config).filter(Config.id == 1).first()
    pdf_bytes = generate_report(campaign, campaign.results, config)

    filename = f"truevector_{campaign.id}_{campaign.name[:30].replace(' ', '_')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Delete ────────────────────────────────────────────────────────────────────

@router.post("/campaigns/{campaign_id}/delete")
async def campaign_delete(campaign_id: int, request: Request, db: Session = Depends(get_db)):
    user = _auth(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if campaign:
        db.delete(campaign)
        db.commit()
    return RedirectResponse("/campaigns", status_code=302)
