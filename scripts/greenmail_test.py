r"""
REAL integration test against GreenMail (local SMTP + IMAP).

Exercises the full production pipeline: sender.py sends via SMTP, the worker waits,
and reader.py reads back via IMAP and classifies. GreenMail delivers everything to
the inbox (it is not a gateway), so it validates the flow — not real classification.

Requirements: GreenMail running (started by scripts/run_greenmail.ps1).
  SMTP 127.0.0.1:3025 (STARTTLS) · IMAP-SSL 127.0.0.1:3993 · auth disabled.

Run:  python scripts/greenmail_test.py
"""

import os
import sys
import ssl

# ── Environment config (before importing the app) ──────────────────────────────
os.environ["DATABASE_URL"] = "sqlite:///./data/greenmail_test.db"
os.environ.setdefault("SECRET_KEY", "gm-test")
os.environ.setdefault("ADMIN_PASSWORD", "gm-test")
# Short wait times: GreenMail delivers instantly
os.environ["READ_FIRST_TIMEOUT"] = "30"
os.environ["READ_QUIET_PERIOD"] = "2"
os.environ["READ_POLL_INTERVAL"] = "2"
os.environ["READ_ABSOLUTE_TIMEOUT"] = "60"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── GreenMail self-signed cert: disable verification ONLY in this test ─────────
_orig_ctx = ssl.create_default_context
def _unverified(*a, **k):
    ctx = _orig_ctx(*a, **k)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
ssl.create_default_context = _unverified

import json

DB_FILE = os.path.join("data", "greenmail_test.db")
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

from app.database import Base, engine, SessionLocal
from app.models import Config, Campaign, Result
from app.core.worker import run_campaign

Base.metadata.create_all(bind=engine)

_passed, _failed = 0, 0
def check(name, cond, detail=""):
    global _passed, _failed
    if cond: _passed += 1; print(f"  [OK]   {name}")
    else:    _failed += 1; print(f"  [FAIL] {name}  {detail}")

# ── Configure pointing at GreenMail ────────────────────────────────────────────
db = SessionLocal()
db.add(Config(
    id=1,
    smtp_host="127.0.0.1", smtp_port=3025,
    smtp_user="probe@localhost", smtp_pass="secret",
    from_domain="localhost", from_name="Security Validator",
    target_email="tester@localhost",
    imap_host="127.0.0.1", imap_port=3993,
    imap_user="tester@localhost", imap_pass="secret",
))
camp = Campaign(
    name="GreenMail integration",
    selected_techniques=json.dumps(["T01", "T05", "T09", "T14"]),
    status="running",
)
db.add(camp)
db.commit()
camp_id = camp.id
db.close()

print("\nSending via SMTP and reading back via IMAP (real code)...")
run_campaign(camp_id)  # real send mode

# ── Verify ──────────────────────────────────────────────────────────────────────
db = SessionLocal()
camp = db.query(Campaign).filter(Campaign.id == camp_id).first()
results = {r.technique_id: r for r in db.query(Result).filter(Result.campaign_id == camp_id).all()}

print(f"\nStatus: {camp.status}  ·  score: {camp.score}%")
for tid, r in sorted(results.items()):
    print(f"  {tid}: placement={r.placement}  msgid={r.message_id}  adj_rx={r.attachment_names_rx}")

check("campaign finished (done)", camp.status == "done", f"(status={camp.status})")
check("4 results", len(results) == 4, f"(n={len(results)})")
check("all delivered (INBOX) — GreenMail doesn't filter",
      all(r.placement == "INBOX" for r in results.values()),
      f"({[r.placement for r in results.values()]})")
check("score 0% (everything reached the inbox)", camp.score == 0.0, f"(score={camp.score})")
# Attachment round-trip
check("T09: eicar.com received intact",
      results["T09"].attachment_names_rx and "eicar.com" in results["T09"].attachment_names_rx,
      f"(rx={results['T09'].attachment_names_rx})")
check("T05: report.docm received intact",
      results["T05"].attachment_names_rx and "report.docm" in results["T05"].attachment_names_rx,
      f"(rx={results['T05'].attachment_names_rx})")
check("message-id captured in all", all(r.message_id for r in results.values()))
db.close()

print(f"\n{'='*50}\nRESULT: {_passed} OK, {_failed} FAILED\n{'='*50}")
engine.dispose()
try:
    if os.path.exists(DB_FILE): os.remove(DB_FILE)
except OSError:
    pass
sys.exit(1 if _failed else 0)
