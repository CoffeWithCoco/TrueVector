r"""
Self-check / smoke test — validates the full flow WITHOUT external services.

Uses a temporary database and exercises:
  - startup (user creation + orphaned-campaign sweep)
  - end-to-end demo mode (worker -> results -> score)
  - exclusion of NOT_FOUND from the score
  - real display-name spoofing (T12)
  - the reader's two-phase polling (with a simulated IMAP)
  - PDF generation

Run:  python scripts/selfcheck.py
"""

import os
import sys

# Isolated temporary DB — must be set BEFORE importing the app
os.environ["DATABASE_URL"] = "sqlite:///./data/selfcheck.db"
os.environ.setdefault("SECRET_KEY", "selfcheck-secret")
os.environ.setdefault("ADMIN_PASSWORD", "selfcheck-pass")

# Allow importing the app package from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DB_FILE = os.path.join("data", "selfcheck.db")
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

import asyncio
import json
import time

_passed, _failed = 0, 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [OK]   {name}")
    else:
        _failed += 1
        print(f"  [FAIL] {name}  {detail}")


# ── 1. Real startup (lifespan): user + orphan sweep ────────────────────────────
print("\n1. Startup (default user + orphaned-campaign sweep)")
from app.main import app, lifespan
from app.database import SessionLocal
from app.models import User, Campaign, Config, Result

# Seed a 'running' orphaned campaign BEFORE startup
_db = SessionLocal()
orphan = Campaign(name="orphan", selected_techniques=json.dumps(["T01"]), status="running")
_db.add(orphan)
_db.commit()
orphan_id = orphan.id
_db.close()


async def _boot():
    async with lifespan(app):
        pass

asyncio.run(_boot())

_db = SessionLocal()
check("admin user created", _db.query(User).filter(User.username == "admin").first() is not None)
swept = _db.query(Campaign).filter(Campaign.id == orphan_id).first()
check("orphaned campaign marked as error", swept.status == "error", f"(status={swept.status})")
_db.close()


# ── 2. End-to-end demo mode ────────────────────────────────────────────────────
print("\n2. Demo-mode campaign (full worker, no SMTP/IMAP)")
from app.core.worker import run_campaign

_db = SessionLocal()
camp = Campaign(
    name="Demo selfcheck",
    selected_techniques=json.dumps(["T01", "T04", "T12", "T14"]),
    status="running",
)
_db.add(camp)
_db.commit()
camp_id = camp.id
_db.close()

t0 = time.time()
run_campaign(camp_id)  # synchronous; demo mode sleeps ~3s
elapsed = time.time() - t0

_db = SessionLocal()
camp = _db.query(Campaign).filter(Campaign.id == camp_id).first()
results = _db.query(Result).filter(Result.campaign_id == camp_id).all()
check("campaign finished (done)", camp.status == "done", f"(status={camp.status})")
check("4 results generated", len(results) == 4, f"(n={len(results)})")
check("score computed", camp.score is not None, f"(score={camp.score})")
check("all results have a valid placement",
      all(r.placement in ("INBOX", "JUNK", "MISSING", "NOT_FOUND") for r in results))
print(f"       score={camp.score}%  placements={[r.placement for r in results]}  ({elapsed:.1f}s)")
_db.close()


# ── 3. NOT_FOUND excluded from the score ───────────────────────────────────────
print("\n3. The score excludes NOT_FOUND")
from app.core.worker import _SCORE_MAP


def _score(placements):
    scored = [p for p in placements if p in _SCORE_MAP]
    return round(sum(_SCORE_MAP[p] for p in scored) / len(scored) * 100, 1) if scored else None

check("all NOT_FOUND -> None (no inflation)", _score(["NOT_FOUND", "NOT_FOUND"]) is None)
check("INBOX+MISSING+NOT_FOUND -> 50.0", _score(["INBOX", "MISSING", "NOT_FOUND"]) == 50.0)
check("all MISSING -> 100.0", _score(["MISSING", "MISSING"]) == 100.0)


# ── 4. Real display-name spoofing (T12) ────────────────────────────────────────
print("\n4. T12 spoofs the display name in From")
from app.techniques.registry import load_all
import types

techs = {t.meta.id: t for t in load_all()}
check("29 techniques loaded", len(techs) == 29, f"(n={len(techs)})")
cfg = types.SimpleNamespace(from_name="Security Validator", smtp_user="probe@test.com", from_domain="test.com")
display = techs["T12"].meta.spoof_from_name or cfg.from_name
check("T12 From uses the spoofed name", display == "PayPal Security Team", f"(={display})")


# ── 5. Reader two-phase polling (simulated IMAP) ───────────────────────────────
print("\n5. Reader: two-phase polling with staggered delivery")
from app.core import reader as rd
from app.core.reader import IMAPReader, AnalysisItem
from email.message import EmailMessage


class _FakeIMAP:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def login(self, *a): pass


def _msg(vid):
    m = EmailMessage(); m["Message-ID"] = f"<{vid}>"; m["Date"] = "Mon, 01 Jan 2026 00:00:00 +0000"
    m.set_content("hi"); return m


_clock = {"t": 0.0}


class _StaggeredReader(IMAPReader):
    def _discover_folders(self, imap): return [("INBOX", "INBOX"), ("Junk", "JUNK")]
    def _find_in_folders(self, imap, folders, vid):
        if vid == "v1": return _msg(vid), "INBOX"          # arrives immediately
        if vid == "v2" and _clock["t"] >= 20: return _msg(vid), "JUNK"  # late
        return None, None                                   # v3 never


rd.imaplib.IMAP4_SSL = lambda *a, **k: _FakeIMAP()
rd.time.monotonic = lambda: _clock["t"]
rd.time.sleep = lambda s: _clock.__setitem__("t", _clock["t"] + 10)

seen = {}
_StaggeredReader("h", 993, "u", "p").wait_and_analyze(
    [AnalysisItem("v1"), AnalysisItem("v2"), AnalysisItem("v3")],
    lambda vid, a: seen.__setitem__(vid, a.placement),
    first_timeout=600, quiet_period=30, poll_interval=10, absolute_timeout=1800,
)
check("v1 (fast)  -> INBOX", seen.get("v1") == "INBOX")
check("v2 (late)  -> JUNK", seen.get("v2") == "JUNK")
check("v3 (never) -> MISSING (blocked, some arrived)", seen.get("v3") == "MISSING")


# ── 6. PDF generation ──────────────────────────────────────────────────────────
print("\n6. PDF report generation")
from app.core.reporter import generate_report

_db = SessionLocal()
camp = _db.query(Campaign).filter(Campaign.id == camp_id).first()
pdf = generate_report(camp, camp.results, _db.query(Config).filter(Config.id == 1).first())
check("PDF generated with %PDF header", pdf[:4] == b"%PDF", f"({len(pdf)} bytes)")
_db.close()


# ── 7. Carrier contamination detector (control canaries) ───────────────────────
print("\n7. Carrier health from control canaries")
from app.core.carrier import assess, split_results, is_canary


class _Row:
    def __init__(self, id, technique_id, placement):
        self.id = id
        self.technique_id = technique_id
        self.placement = placement


# Send order by id: canary(good), T16, T17, canary(good), T05, canary(JUNK), T09
rows = [
    _Row(1, "CANARY-00", "INBOX"),
    _Row(2, "T16", "INBOX"),
    _Row(3, "T17", "MISSING"),
    _Row(4, "CANARY-01", "INBOX"),
    _Row(5, "T05", "INBOX"),
    _Row(6, "CANARY-02", "JUNK"),     # carrier degrades here
    _Row(7, "T09", "INBOX"),          # sent after the drop -> suspect
]
canaries, techs = split_results(rows)
check("split separates canaries from techniques", len(canaries) == 3 and len(techs) == 4)
status, suspect = assess(canaries, techs)
check("degraded carrier detected", status == "degraded", f"(status={status})")
check("technique after the drop is flagged (T09 id=7)", 7 in suspect, f"(suspect={suspect})")
check("technique before the last good canary is clean (T16 id=2)", 2 not in suspect)

# All canaries good -> stable, nothing suspect
good = [_Row(1, "CANARY-00", "INBOX"), _Row(2, "T01", "INBOX"), _Row(3, "CANARY-01", "INBOX")]
gc, gt = split_results(good)
gstatus, gsuspect = assess(gc, gt)
check("all-inbox canaries -> stable, no suspects", gstatus == "stable" and not gsuspect, f"({gstatus})")

# No locatable canaries -> unknown (don't guess)
none_found = [_Row(1, "CANARY-00", "NOT_FOUND"), _Row(2, "T01", "INBOX")]
nc, nt = split_results(none_found)
nstatus, _ = assess(nc, nt)
check("no found canaries -> unknown", nstatus == "unknown", f"({nstatus})")


# ── 8. Graph reader: single-pass multi-ID scan, pagination, body fallback ───────
print("\n8. Graph _scan: one pass matches many IDs (no per-ID re-listing)")
from app.core.reader import GraphAPIReader


def _gm(mid, vid):
    return {
        "id": mid,
        "internetMessageHeaders": [{"name": "X-Validator-ID", "value": vid}],
        "receivedDateTime": "2026-06-23T21:00:00Z",
    }


_calls = {"list": 0}


def _fake_graph_get(path, raw=False):
    if "/$value" in path:
        if "msg-bad" in path:           # calendar-invite-style 500 on body
            raise RuntimeError("HTTP Error 500")
        return b"Subject: t\r\nX-Validator-ID: x\r\n\r\nbody\r\n"
    _calls["list"] += 1
    if "page2" in path:                 # second page via @odata.nextLink
        return {"value": [_gm("msg-5", "v5")]}
    if "mailFolders/inbox/messages" in path:
        return {"value": [_gm("msg-1", "v1"), _gm("msg-bad", "v2")],
                "@odata.nextLink": "https://graph.example/page2"}
    if "mailFolders/junkemail/messages" in path:
        return {"value": [_gm("msg-3", "v3")]}
    return {"value": []}


_g = GraphAPIReader("t", "c", "s", "mbox@example.com")
_g._graph_get = _fake_graph_get
res = _g._scan({"v1", "v2", "v3", "v4", "v5"})

check("v1 found in INBOX with body", res.get("v1") and res["v1"][0] is not None and res["v1"][1] == "INBOX")
check("v2 located but body unavailable (None, INBOX)", res.get("v2") == (None, "INBOX")
      or (res.get("v2") and res["v2"][0] is None and res["v2"][1] == "INBOX"))
check("v3 found in JUNK (folder precedence)", res.get("v3") and res["v3"][1] == "JUNK")
check("v5 found via pagination (@odata.nextLink followed)", res.get("v5") and res["v5"][0] is not None)
check("v4 (absent) not returned", "v4" not in res)
# 5 IDs resolved with only 3 folder-list calls (inbox p1, inbox p2, junk) — not
# one listing per ID, which is the whole point of the single-pass scan.
check("single-pass: <=3 list calls for 5 IDs", _calls["list"] <= 3, f"(calls={_calls['list']})")


# ── Summary ────────────────────────────────────────────────────────────────────
print(f"\n{'='*50}\nRESULT: {_passed} OK, {_failed} FAILED\n{'='*50}")

# Close the temporary DB before deleting it (SQLite keeps it open)
from app.database import engine
engine.dispose()
try:
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
except OSError:
    pass  # best-effort cleanup; does not affect the result

sys.exit(1 if _failed else 0)
