"""
Campaign execution worker.

Runs synchronously in a background thread (see routes/campaigns.py) so its
blocking SMTP/IMAP I/O never freezes the async event loop.

Two modes:
  Send mode  — SMTP + target_email configured → sends real emails, then waits for
               and analyses them via IMAP (two-phase polling, live-updated).
  Mock mode  — no config → waits 3s, generates realistic demo results instantly.
"""

import json
import logging
import random
import time
from datetime import datetime, timezone, timedelta

from ..database import SessionLocal
from ..models import Campaign, Config, Result
from ..techniques.registry import load_all, send_rank

# Mock results keyed by technique ID — simulate a realistic but varied gateway response
_MOCK = {
    "T01": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  links_rewritten=False, banner_injected=True),
    "T02": dict(placement="JUNK",    scl=6,  gateway_category="MALW",  attachments_stripped=False),
    "T03": dict(placement="JUNK",    scl=5,  gateway_category="PHSH",  attachments_stripped=False),
    "T04": dict(placement="MISSING", scl=9,  gateway_category="MALW",  attachments_stripped=True),
    "T05": dict(placement="MISSING", scl=9,  gateway_category="MALW",  attachments_stripped=True),
    "T06": dict(placement="INBOX",   scl=2,  gateway_category="NONE"),
    "T07": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  links_rewritten=False),
    "T08": dict(placement="JUNK",    scl=4,  gateway_category="BULK"),
    "T09": dict(placement="MISSING", scl=9,  gateway_category="MALW",  attachments_stripped=True),
    "T10": dict(placement="JUNK",    scl=7,  gateway_category="PHSH",  links_rewritten=True),
    "T11": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  images_present=True,  images_proxied=False),
    "T12": dict(placement="INBOX",   scl=3,  gateway_category="SPOOF", banner_injected=True),
    "T13": dict(placement="JUNK",    scl=6,  gateway_category="PHSH",  links_rewritten=True),
    "T14": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),
    "T15": dict(placement="JUNK",    scl=5,  gateway_category="MALW"),
    # T16-T28 — new vectors
    "T16": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),   # Blob API invisible to the gateway
    "T17": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),   # external link, gateway never sees payload
    "T18": dict(placement="INBOX",   scl=2,  gateway_category="NONE",  attachments_stripped=False),  # encrypted ZIP
    "T19": dict(placement="JUNK",    scl=6,  gateway_category="MALW",  attachments_stripped=False),  # modern ISO
    "T20": dict(placement="JUNK",    scl=5,  gateway_category="MALW",  attachments_stripped=False),  # OneNote
    "T21": dict(placement="JUNK",    scl=7,  gateway_category="MALW",  attachments_stripped=True),   # PDF JS
    "T22": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  links_rewritten=False),       # open redirect
    "T23": dict(placement="INBOX",   scl=3,  gateway_category="SPOOF", banner_injected=True),        # BEC Reply-To
    "T24": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),   # MIME mismatch invisible
    "T25": dict(placement="MISSING", scl=9,  gateway_category="MALW",  attachments_stripped=True),   # LNK blocked
    "T26": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),   # undecoded HTML entities
    "T27": dict(placement="INBOX",   scl=1,  gateway_category="NONE"),   # dynamic URL invisible
    "T28": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  images_present=True),         # opaque QR
    "T29": dict(placement="INBOX",   scl=1,  gateway_category="NONE",  links_rewritten=False),       # trusted-host bypass
}

_SCORE_MAP = {"MISSING": 1.0, "JUNK": 0.5, "INBOX": 0.0}


def _since_filter(campaign) -> "str | None":
    """ISO-8601 UTC lower bound for the mailbox search, derived from when the
    campaign was created (minus a buffer for clock skew / pre-send creation).
    Lets the Graph reader confine its search to recent messages so a reused test
    mailbox with thousands of old messages is never paged through."""
    ts = getattr(campaign, "created_at", None)
    if not ts:
        return None
    return (ts - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_persist(db, result_rows):
    """Return a persist(vid, analysis) callback that writes one analysis onto its
    Result row and commits (so the live campaign page updates incrementally)."""
    row_by_vid = {row.validator_id: row for row, _ in result_rows if row.validator_id}

    def persist(vid: str, analysis) -> None:
        row = row_by_vid.get(vid)
        if row is None:
            return
        if analysis.found:
            row.placement            = analysis.placement
            row.scl                  = analysis.scl
            row.gateway_category     = analysis.gateway_category
            row.spf                  = analysis.spf
            row.dkim                 = analysis.dkim
            row.dmarc                = analysis.dmarc
            row.links_rewritten      = analysis.links_rewritten
            row.banner_injected      = analysis.banner_injected
            row.body_modified        = analysis.body_modified
            row.attachments_stripped = analysis.attachments_stripped
            row.images_present       = analysis.images_present
            row.images_stripped      = analysis.images_stripped
            row.images_proxied       = analysis.images_proxied
            row.message_id           = analysis.message_id
            row.delivered_at         = analysis.delivered_at
            if analysis.attachments_received:
                row.attachment_names_rx = json.dumps(analysis.attachments_received)
            if analysis.gateway_raw:
                row.gateway_raw = json.dumps(analysis.gateway_raw)
        else:
            row.placement = analysis.placement  # MISSING or NOT_FOUND
        db.commit()

    return persist


def _run_reader(db, config, result_rows, *, since=None, timeouts=None) -> None:
    """Read back and analyse the given (Result, technique) rows via the configured
    backend. Shared by the live worker and the re-analyze action. Send failures
    (err-/skip-/mock- ids) are skipped. Reader exceptions are logged, leaving the
    affected rows at their current placement."""
    from .reader import reader_from_config, AnalysisItem

    persist = _build_persist(db, result_rows)
    items = [
        AnalysisItem(
            validator_id=row.validator_id,
            expected_attachments=(technique.meta.expected_attachments if technique else []),
            expected_images=(technique.meta.expected_images if technique else False),
        )
        for row, technique in result_rows
        if row.validator_id
        and not row.validator_id.startswith(("err-", "skip-", "mock-"))
    ]
    if not items:
        return
    try:
        reader = reader_from_config(config)
        reader.wait_and_analyze(items, persist, since=since, **(timeouts or {}))
    except Exception as exc:
        logging.getLogger(__name__).error("Mailbox reader failed: %s", exc)


def _score_and_finalize(db, campaign, result_rows) -> None:
    """Compute the protection score + carrier health from result_rows and mark
    the campaign done. Only conclusive, non-canary results count toward the score
    (NOT_FOUND excluded). Shared by the live worker and the re-analyze action."""
    from .carrier import assess, is_canary

    scored = [r for r, _ in result_rows if r.placement in _SCORE_MAP and not is_canary(r)]
    campaign.score = (
        round(sum(_SCORE_MAP[r.placement] for r in scored) / len(scored) * 100, 1)
        if scored else None
    )

    canary_rows = [r for r, _ in result_rows if is_canary(r)]
    tech_rows = [r for r, _ in result_rows if not is_canary(r)]
    status, suspect_ids = assess(canary_rows, tech_rows)
    campaign.carrier_status = status
    for r in tech_rows:
        r.carrier_suspect = r.id in suspect_ids

    campaign.status = "done"
    campaign.finished_at = datetime.now(timezone.utc)
    db.commit()


def run_campaign(campaign_id: int) -> None:
    db = SessionLocal()
    campaign = None
    try:
        campaign: Campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not campaign:
            return

        config: Config | None = db.query(Config).filter(Config.id == 1).first()
        mock_mode = not (config and config.smtp_host and config.target_email)

        # Deploy-specific URLs for hosted-payload techniques (T17/T28/T29).
        from ..techniques.base import RuntimeContext
        ctx = RuntimeContext(
            web_base_url=(config.web_base_url or "") if config else "",
            cloud_payload_url=(config.cloud_payload_url or "") if config else "",
        )

        technique_ids: list[str] = json.loads(campaign.selected_techniques or "[]")
        # Send stealthiest payloads first, loudest (EICAR/macro) last, so a
        # reputation hit late in the run can't contaminate the subtle techniques.
        technique_ids.sort(key=send_rank)
        all_techniques = {t.meta.id: t for t in load_all()}

        # Pacing between real sends (seconds) + random jitter so the run doesn't
        # look like a cron. Spacing keeps the sender's reputation stable across the
        # whole campaign so per-technique verdicts stay comparable. 0 = burst.
        interval = max(0, (config.send_interval if config and config.send_interval is not None else 0))
        jitter = max(0, (config.send_jitter if config and config.send_jitter is not None else 0))

        # Control canaries: benign emails interleaved with the techniques to probe
        # the sender's reputation live. Only meaningful for real sends, so they're
        # off in demo mode. Plan: a baseline canary before the first technique, one
        # every N techniques, and a final checkpoint at the end.
        canaries_on = (not mock_mode) and bool(config and config.canaries_enabled)
        canary_every = max(1, (config.canary_every if config and config.canary_every else 7))

        valid_techs = [all_techniques[t] for t in technique_ids if t in all_techniques]
        plan: list[tuple[str, object]] = []
        if canaries_on:
            plan.append(("canary", None))
        for i, tech in enumerate(valid_techs):
            plan.append(("tech", tech))
            if canaries_on and (i + 1) % canary_every == 0 and (i + 1) < len(valid_techs):
                plan.append(("canary", None))
        if canaries_on:
            plan.append(("canary", None))

        def _pace():
            # Wait interval ± jitter before a real send (never before the first) so
            # the gateway sees organic-looking traffic instead of a burst.
            if sent_any and interval > 0:
                time.sleep(max(0.0, interval + random.uniform(-jitter, jitter)))

        # ── Create Result rows + send ─────────────────────────────────────────
        result_rows: list[tuple[Result, object]] = []
        sent_any = False
        canary_idx = 0
        for kind, tech in plan:
            if kind == "canary":
                _pace()
                try:
                    from .sender import send_canary
                    validator_id = send_canary(config, campaign_id, config.target_email, canary_idx)
                    sent_any = True
                except Exception:
                    validator_id = f"err-{campaign_id}-CANARY{canary_idx:02d}"
                row = Result(
                    campaign_id=campaign_id,
                    technique_id=f"CANARY-{canary_idx:02d}",
                    technique_name="Control canary (benign)",
                    threat="Carrier reputation probe - benign email; measures sender standing, not a gateway control.",
                    validator_id=validator_id,
                    placement="NOT_FOUND",
                )
                db.add(row)
                db.commit()
                result_rows.append((row, None))
                canary_idx += 1
                continue

            technique = tech
            validator_id = f"mock-{campaign_id}-{technique.meta.id}" if mock_mode else None
            skip_note = None

            if not mock_mode:
                # Gate hosted-payload techniques: if the required Payload-hosting field
                # is not configured, skip sending instead of emitting a broken placeholder.
                requires = technique.meta.requires
                if requires and not getattr(ctx, requires, ""):
                    validator_id = f"skip-{campaign_id}-{technique.meta.id}"
                    skip_note = f"Not executed: requires '{requires}' (Settings -> Payload hosting)."
                else:
                    _pace()
                    try:
                        from .sender import send_technique
                        validator_id = send_technique(
                            config, technique, campaign_id, config.target_email, ctx=ctx
                        )
                        sent_any = True
                    except Exception:
                        validator_id = f"err-{campaign_id}-{technique.meta.id}"

            row = Result(
                campaign_id=campaign_id,
                technique_id=technique.meta.id,
                technique_name=technique.meta.name,
                threat=technique.meta.threat,
                validator_id=validator_id,
                # Unknown until analysed. NOT_FOUND is excluded from scoring so a
                # read failure never inflates the protection score.
                placement="NOT_FOUND",
            )
            if skip_note:
                row.gateway_raw = json.dumps({"skipped": skip_note})
            db.add(row)
            db.commit()  # commit per send so the campaign page shows progress live
            result_rows.append((row, technique))

        # ── Analyse ───────────────────────────────────────────────────────────
        if mock_mode:
            time.sleep(3)
            for row, technique in result_rows:
                mock = _MOCK.get(technique.meta.id, {})
                row.placement            = mock.get("placement", "MISSING")
                row.scl                  = mock.get("scl")
                row.gateway_category     = mock.get("gateway_category")
                row.spf                  = "pass"
                row.dkim                 = "pass" if technique.meta.id not in ("T12",) else "fail"
                row.dmarc                = "pass" if technique.meta.id not in ("T12",) else "fail"
                row.links_rewritten      = mock.get("links_rewritten", False)
                row.banner_injected      = mock.get("banner_injected", False)
                row.body_modified        = row.links_rewritten or row.banner_injected
                row.attachments_stripped = mock.get("attachments_stripped", False)
                row.images_present       = mock.get("images_present", False)
                row.images_proxied       = mock.get("images_proxied", False)
                row.delivered_at         = datetime.now(timezone.utc)
        else:
            # Two-phase wait: hold for the first message to land, then keep
            # resolving each arrival live until a quiet period passes. Each
            # resolved message is committed immediately so the campaign page
            # (auto-refreshing every 5s) shows progress in real time. Confine the
            # Graph search to messages received since the campaign was created.
            _run_reader(db, config, result_rows, since=_since_filter(campaign))

        db.commit()

        # Score + carrier health, then mark done (NOT_FOUND excluded from score;
        # canaries feed only the carrier assessment).
        _score_and_finalize(db, campaign, result_rows)

    except Exception:
        if campaign:
            campaign.status = "error"
            db.commit()
    finally:
        db.close()


def reanalyze_campaign(campaign_id: int) -> None:
    """Re-read the mailbox for an already-sent campaign and re-classify the
    results that are still inconclusive (NOT_FOUND) — WITHOUT resending anything.

    Recovers from transient read failures, late/sandboxed delivery or a reader
    misconfiguration fixed after the run, without burning the sending account or
    re-triggering the gateway. Conclusive rows (INBOX/JUNK/MISSING) are left
    untouched, so a transient re-read can never downgrade a good verdict."""
    db = SessionLocal()
    campaign = None
    try:
        campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not campaign:
            return

        config: Config | None = db.query(Config).filter(Config.id == 1).first()
        if not (config and config.smtp_host and config.target_email):
            # No reader configured (e.g. a demo campaign) — nothing to re-read.
            campaign.status = "done"
            db.commit()
            return

        all_techniques = {t.meta.id: t for t in load_all()}
        rows = db.query(Result).filter(Result.campaign_id == campaign_id).all()
        result_rows = [(r, all_techniques.get(r.technique_id)) for r in rows]

        # Only re-read the still-inconclusive, actually-sent rows.
        to_read = [
            (r, t) for r, t in result_rows
            if r.placement == "NOT_FOUND"
            and r.validator_id
            and not r.validator_id.startswith(("err-", "skip-", "mock-"))
        ]

        # Messages are already delivered — use a short budget (a few scan passes
        # to absorb a transient error), not the full live-delivery wait.
        _run_reader(db, config, to_read, since=_since_filter(campaign), timeouts={
            "first_timeout": 30, "quiet_period": 8,
            "poll_interval": 8, "absolute_timeout": 150,
        })

        db.commit()
        _score_and_finalize(db, campaign, result_rows)

    except Exception:
        if campaign:
            campaign.status = "error"
            db.commit()
    finally:
        db.close()
