"""PDF report generator — TrueVector Email Attack Surface Validator.

Light theme, high contrast, built to be read by a pentester/red-teamer who is NOT
necessarily an email-security specialist: a plain-language executive summary up
front, technical detail (with a legend) afterwards.
"""

from datetime import datetime
from fpdf import FPDF, XPos, YPos

from .risk import (
    CRITICAL, HIGH, MEDIUM, LOW, PASS,
    RISK_COLOR_PDF, RISK_ORDER,
    detect_chains, overall_risk, result_risk,
)


def _s(text: str) -> str:
    """Sanitize string to Latin-1 for the Helvetica core font."""
    return (
        text.replace("—", "-")
            .replace("–", "-")
            .replace("'", "'")
            .replace("'", "'")
            .replace("“", '"')
            .replace("”", '"')
            .replace("…", "...")
            .encode("latin-1", errors="replace")
            .decode("latin-1")
    )


# ── Light palette ───────────────────────────────────────────────────────────
_INK     = (15,  23,  42)    # slate-900 — headings / strong text
_BODY    = (51,  65,  85)    # slate-700 — body text
_MUTED   = (100, 116, 139)   # slate-500 — labels / secondary
_LINE    = (203, 213, 225)   # slate-300 — borders / rules
_PANEL   = (246, 248, 251)   # near-white — tile / card fill
_PANEL2  = (236, 240, 246)   # slightly darker panel (table header)
_ACCENT  = (79,  70,  229)   # indigo-600 — brand / section accents
_WHITE   = (255, 255, 255)

# Risk colors (shared with the app via risk.py)
_CRIT  = RISK_COLOR_PDF[CRITICAL]
_HIGH  = RISK_COLOR_PDF[HIGH]
_MED   = RISK_COLOR_PDF[MEDIUM]
_LOW   = RISK_COLOR_PDF[LOW]
_PASS  = RISK_COLOR_PDF[PASS]
_ORANGE = (234, 88, 12)


def _tc(pdf: FPDF, rgb): pdf.set_text_color(*rgb)
def _fc(pdf: FPDF, rgb): pdf.set_fill_color(*rgb)
def _dc(pdf: FPDF, rgb): pdf.set_draw_color(*rgb)

def _risk_color(risk: str):
    return RISK_COLOR_PDF.get(risk, _MUTED)

def _risk_label(risk: str) -> str:
    return {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", PASS: "OK"}.get(risk, risk)

def _placement_label(p: str) -> str:
    return {
        "INBOX": "Inbox",
        "JUNK": "Junk",
        "MISSING": "Blocked",
        "NOT_FOUND": "Inconcl.",
    }.get(p, p)

def _placement_color(p: str):
    return {"INBOX": _CRIT, "JUNK": _ORANGE, "MISSING": _PASS, "NOT_FOUND": _MUTED}.get(p, _MUTED)


def _verdict(score):
    """Plain-language verdict word + color from the protection score."""
    if score is None:
        return "INCONCLUSIVE", _MUTED
    if score >= 80:
        return "STRONG", _PASS
    if score >= 50:
        return "MODERATE", _MED
    if score >= 1:
        return "WEAK", _HIGH
    return "CRITICAL", _CRIT


class _PDF(FPDF):
    def __init__(self, campaign_name: str):
        super().__init__()
        self._campaign = _s(campaign_name)

    def cell(self, w=0, h=0, text="", *args, **kwargs):
        return super().cell(w, h, _s(str(text)), *args, **kwargs)

    def multi_cell(self, w, h=0, text="", *args, **kwargs):
        return super().multi_cell(w, h, _s(str(text)), *args, **kwargs)

    def header(self):
        if self.page_no() == 1:
            return
        _tc(self, _MUTED)
        self.set_font("Helvetica", "", 7.5)
        self.set_xy(10, 8)
        self.cell(120, 5, "TrueVector - Email Attack Surface Report")
        self.set_xy(90, 8)
        self.cell(110, 5, self._campaign[:55], align="R")
        _dc(self, _LINE)
        self.set_line_width(0.2)
        self.line(10, 14, 200, 14)
        self.set_y(20)

    def footer(self):
        self.set_y(-12)
        _dc(self, _LINE)
        self.set_line_width(0.2)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(1.5)
        _tc(self, _MUTED)
        self.set_font("Helvetica", "", 7)
        self.cell(120, 5, "TrueVector - Authorized use only")
        self.cell(0, 5, f"Page {self.page_no()}", align="R")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_title(pdf: _PDF, title: str, subtitle: str = ""):
    pdf.ln(3)
    y = pdf.get_y()
    _fc(pdf, _ACCENT)
    pdf.rect(10, y + 0.8, 2.6, 6, style="F")
    _tc(pdf, _INK)
    pdf.set_font("Helvetica", "B", 12.5)
    pdf.set_xy(15, y)
    pdf.cell(0, 7.5, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if subtitle:
        pdf.set_x(15)
        _tc(pdf, _MUTED)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 4.5, subtitle, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    _dc(pdf, _LINE)
    pdf.set_line_width(0.3)
    pdf.line(10, pdf.get_y() + 1, 200, pdf.get_y() + 1)
    pdf.ln(4)


def _risk_badge(pdf: _PDF, risk: str, x: float, y: float, w: float = 22, h: float = 5.5):
    color = _risk_color(risk)
    _fc(pdf, color)
    pdf.rect(x, y, w, h, style="F")
    _tc(pdf, _WHITE)
    pdf.set_font("Helvetica", "B", 6.8)
    pdf.set_xy(x, y + 0.4)
    pdf.cell(w, h - 0.8, _risk_label(risk), align="C")


def _estimate_lines(text: str, chars_per_line: int) -> int:
    if not text:
        return 0
    return max(1, (len(text) + chars_per_line - 1) // chars_per_line)


def _top_actions(chains: list) -> list[str]:
    """Highest-impact, de-duplicated remediation actions across detected chains."""
    actions: list[str] = []
    seen: set[str] = set()
    for entry in sorted(chains, key=lambda e: RISK_ORDER.get(e["chain"].severity, 0), reverse=True):
        for a in entry["chain"].remediation:
            if a not in seen:
                seen.add(a)
                actions.append(a)
            if len(actions) >= 3:
                return actions
    return actions


# ── Page 1: title + executive summary ──────────────────────────────────────────

def _cover(pdf: _PDF, campaign, config, results, chains, demo_mode=False):
    inbox   = sum(1 for r in results if r.placement == "INBOX")
    junk    = sum(1 for r in results if r.placement == "JUNK")
    blocked = sum(1 for r in results if r.placement == "MISSING")
    notfound = sum(1 for r in results if r.placement == "NOT_FOUND")
    crits   = sum(1 for r in results if result_risk(r) == CRITICAL)
    total   = len(results)
    conclusive = inbox + junk + blocked

    # Header band
    _fc(pdf, _ACCENT)
    pdf.rect(0, 0, 210, 30, style="F")
    _tc(pdf, _WHITE)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(10, 7)
    pdf.cell(0, 10, "TrueVector")
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_xy(10, 18)
    pdf.cell(0, 5, "Email Attack Surface Report")

    # Demo ribbon
    if demo_mode:
        _fc(pdf, _ORANGE)
        pdf.rect(0, 30, 210, 7, style="F")
        _tc(pdf, _WHITE)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_xy(10, 31)
        pdf.cell(190, 5, "DEMO MODE - Simulated results, not a real send", align="C")

    y = 44 if demo_mode else 38

    # Campaign title + meta
    _tc(pdf, _INK)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_xy(10, y)
    pdf.multi_cell(190, 8, campaign.name[:80])
    y = pdf.get_y() + 1
    _tc(pdf, _MUTED)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_xy(10, y)
    ts = datetime.now().strftime("%d %b %Y, %H:%M")
    target = (config.target_email if config and config.target_email else "—")
    pdf.cell(0, 5, f"Generated {ts}   |   Target mailbox: {target}")
    y = pdf.get_y() + 6

    # ── Score + verdict panel ──────────────────────────────────────────────────
    score = campaign.score
    vword, vcolor = _verdict(score)
    panel_h = 26
    _fc(pdf, _PANEL)
    _dc(pdf, _LINE)
    pdf.set_line_width(0.3)
    pdf.rect(10, y, 190, panel_h, style="DF")

    # Score number (left)
    _tc(pdf, vcolor)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_xy(14, y + 3)
    pdf.cell(46, 16, f"{score}%" if score is not None else "N/A")
    _tc(pdf, _MUTED)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_xy(14, y + 19)
    pdf.cell(46, 4, "Protection score")

    # Verdict word (middle)
    _dc(pdf, _LINE)
    pdf.line(72, y + 4, 72, y + panel_h - 4)
    _tc(pdf, _MUTED)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_xy(78, y + 5)
    pdf.cell(0, 4, "GATEWAY DEFENSE")
    _tc(pdf, vcolor)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_xy(78, y + 9)
    pdf.cell(0, 10, vword)

    # Overall-risk badge (right)
    ovr = overall_risk(results)
    _tc(pdf, _MUTED)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_xy(150, y + 5)
    pdf.cell(46, 4, "HIGHEST RISK", align="R")
    _fc(pdf, _risk_color(ovr))
    pdf.rect(158, y + 10, 38, 10, style="F")
    _tc(pdf, _WHITE)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_xy(158, y + 11.5)
    pdf.cell(38, 7, _risk_label(ovr), align="C")

    y += panel_h + 6

    # ── Metric tiles (3 × 2) ────────────────────────────────────────────────────
    tiles = [
        ("Techniques sent",  str(total),    _INK),
        ("Reached inbox",    str(inbox),    _CRIT),
        ("Sent to junk",     str(junk),     _ORANGE),
        ("Blocked",          str(blocked),  _PASS),
        ("Critical findings",str(crits),    _CRIT),
        ("Attack scenarios", str(len(chains)), _ACCENT),
    ]
    tw, th, gap = 60, 20, 5
    for i, (label, val, color) in enumerate(tiles):
        row, col = divmod(i, 3)
        bx = 10 + col * (tw + gap)
        by = y + row * (th + gap)
        _fc(pdf, _PANEL)
        _dc(pdf, _LINE)
        pdf.set_line_width(0.3)
        pdf.rect(bx, by, tw, th, style="DF")
        _tc(pdf, color)
        pdf.set_font("Helvetica", "B", 19)
        pdf.set_xy(bx + 4, by + 2.5)
        pdf.cell(tw - 8, 10, val)
        _tc(pdf, _MUTED)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_xy(bx + 4, by + 13.5)
        pdf.cell(tw - 8, 4, label)
    y += 2 * th + gap + 6

    # ── Carrier health note (only when the sender reputation degraded) ──────────
    if getattr(campaign, "carrier_status", None) == "degraded":
        suspect_n = sum(1 for r in results if getattr(r, "carrier_suspect", False))
        strip_h = 13
        _fc(pdf, (254, 243, 235))
        _dc(pdf, _ORANGE)
        pdf.set_line_width(0.3)
        pdf.rect(10, y, 190, strip_h, style="DF")
        _fc(pdf, _ORANGE)
        pdf.rect(10, y, 2.6, strip_h, style="F")
        _tc(pdf, _ORANGE)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_xy(16, y + 1.8)
        pdf.cell(0, 4, "Carrier degraded mid-run - some results may be contaminated")
        _tc(pdf, _BODY)
        pdf.set_font("Helvetica", "", 7.6)
        pdf.set_xy(16, y + 6)
        pdf.multi_cell(180, 3.7,
            f"Control canaries show the sender's reputation dropped during the run. {suspect_n} technique(s) "
            "sent afterwards are flagged carrier-suspect (marked * below): their verdict may reflect the "
            "burned sender, not the payload. Re-send those from a fresh sender to confirm.")
        y = pdf.get_y() + 5

    # ── Executive summary (plain language) ──────────────────────────────────────
    pdf.set_xy(10, y)
    _section_title(pdf, "Executive summary")

    if score is None:
        narrative = (
            f"We sent {total} known email-attack techniques to the test mailbox, but not "
            f"enough of them could be confirmed in the mailbox to score the gateway "
            f"(inconclusive: {notfound}). Re-run the campaign and confirm mailbox access."
        )
    else:
        bottom = {
            "STRONG":   "Bottom line: the gateway blocked or quarantined most attacks. Keep monitoring and close the remaining gaps.",
            "MODERATE": "Bottom line: there are meaningful gaps. Several attacks reached users who are one click away from compromise.",
            "WEAK":     "Bottom line: the gateway let most attacks through. This is an exploitable foothold for an attacker today.",
            "CRITICAL": "Bottom line: the gateway stopped almost nothing. Treat this as an active, high-priority exposure.",
            "INCONCLUSIVE": "",
        }[vword]
        narrative = (
            f"This assessment sent {total} known email-attack techniques (phishing, malware "
            f"attachments, spoofing and evasion tricks) to the test mailbox and measured what "
            f"the email security gateway did with each one. {inbox} reached the inbox, "
            f"{junk} were diverted to Junk, and {blocked} were blocked outright"
            + (f" ({notfound} inconclusive, excluded from the score)." if notfound else ".")
            + " Anything that reaches the inbox is one click away from a user - the gateway "
            f"did not stop it. The protection score is the share of attacks that were "
            f"blocked or quarantined. {bottom}"
        )

    _tc(pdf, _BODY)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_x(10)
    pdf.multi_cell(190, 5, narrative)
    pdf.ln(3)

    # Top recommended actions
    actions = _top_actions(chains)
    if actions:
        _tc(pdf, _INK)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_x(10)
        pdf.cell(0, 6, "Top recommended actions", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for i, action in enumerate(actions, 1):
            _tc(pdf, _ACCENT)
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.set_x(12)
            pdf.cell(7, 5, f"{i}.")
            _tc(pdf, _BODY)
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(181, 5, action)
            pdf.ln(0.5)
    elif score is not None and inbox == 0:
        _tc(pdf, _PASS)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_x(10)
        pdf.multi_cell(190, 5, "No attack scenarios were triggered - no technique reached the inbox. "
                               "Maintain current controls and re-test after any gateway change.")


# ── Attack scenarios ────────────────────────────────────────────────────────────

def _chains_section(pdf: _PDF, chains: list):
    if not chains:
        return
    _section_title(
        pdf, f"Attack scenarios ({len(chains)})",
        "Real-world intrusions these gaps enable when chained together.",
    )

    for entry in chains:
        chain = entry["chain"]
        trig  = entry["triggered_by"]
        color = _risk_color(chain.severity)

        desc_lines   = _estimate_lines(chain.description[:300], 92)
        impact_lines = _estimate_lines(chain.impact[:200], 96)
        card_h = 11 + desc_lines * 4.3 + 4.5 + impact_lines * 4.3 + 6
        card_h = max(card_h, 30)

        if pdf.get_y() + card_h > 272:
            pdf.add_page()

        y0 = pdf.get_y()
        _fc(pdf, _PANEL)
        _dc(pdf, _LINE)
        pdf.set_line_width(0.3)
        pdf.rect(10, y0, 190, card_h, style="DF")
        _fc(pdf, color)
        pdf.rect(10, y0, 2.6, card_h, style="F")

        # Title row
        _tc(pdf, _INK)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_xy(16, y0 + 2.5)
        pdf.cell(150, 6, f"{chain.id}   {chain.name}")
        _risk_badge(pdf, chain.severity, 172, y0 + 2.8, 22, 5.5)

        # Description
        _tc(pdf, _BODY)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_xy(16, y0 + 9.5)
        pdf.multi_cell(178, 4.3, chain.description[:300])

        # Impact
        pdf.set_x(16)
        _tc(pdf, _CRIT)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(17, 4.3, "Impact: ")
        _tc(pdf, _BODY)
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(161, 4.3, chain.impact[:200])

        # Trigger + MITRE
        _tc(pdf, _MUTED)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_xy(16, pdf.get_y() + 0.5)
        pdf.cell(0, 4, f"Triggered by {', '.join(trig)}   |   MITRE ATT&CK: {chain.mitre}",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_y(y0 + card_h + 4)


# ── Findings table ──────────────────────────────────────────────────────────────

def _findings_table(pdf: _PDF, results):
    if pdf.get_y() > 235:
        pdf.add_page()
    _section_title(
        pdf, "Findings by technique",
        "Per-technique detail. Delivery is the key column: Inbox = got through, Blocked = stopped.",
    )

    cols = [
        ("ID",           12),
        ("Technique",    58),
        ("Risk",         20),
        ("Delivery",     24),
        ("Gateway verdict", 36),
        ("Transformations", 40),
    ]
    row_h = 6.4
    hdr_h = 7
    x0    = 10

    def _draw_header():
        _fc(pdf, _PANEL2)
        pdf.rect(x0, pdf.get_y(), sum(w for _, w in cols), hdr_h, style="F")
        _tc(pdf, _INK)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_x(x0)
        for label, w in cols:
            pdf.cell(w, hdr_h, label, new_x=XPos.RIGHT, new_y=YPos.LAST)
        pdf.ln(hdr_h)

    _draw_header()
    zebra = False

    for r in results:
        if pdf.get_y() + row_h > 272:
            pdf.add_page()
            _draw_header()
            zebra = False

        risk = result_risk(r)

        verdict = " ".join(filter(None, [
            r.gateway_category or "",
            f"SCL {r.scl}" if r.scl is not None else "",
        ])) or "no spam headers"

        tx = []
        if r.links_rewritten:      tx.append("links rewritten")
        if r.banner_injected:      tx.append("banner")
        if r.attachments_stripped: tx.append("attach. stripped")
        if r.images_stripped:      tx.append("images stripped")
        if r.images_proxied:       tx.append("images proxied")
        transforms = ", ".join(tx) or "none"

        y0 = pdf.get_y()
        if zebra:
            _fc(pdf, _PANEL)
            pdf.rect(x0, y0, sum(w for _, w in cols), row_h, style="F")
        zebra = not zebra

        pdf.set_x(x0)
        _tc(pdf, _MUTED)
        pdf.set_font("Helvetica", "", 7.3)
        tid = r.technique_id + (" *" if getattr(r, "carrier_suspect", False) else "")
        pdf.cell(cols[0][1], row_h, tid)

        _tc(pdf, _INK)
        pdf.cell(cols[1][1], row_h, (r.technique_name or "")[:40])

        # risk badge
        bx, by = pdf.get_x(), pdf.get_y()
        _fc(pdf, _risk_color(risk))
        pdf.rect(bx + 1, by + 1, cols[2][1] - 3, row_h - 2, style="F")
        _tc(pdf, _WHITE)
        pdf.set_font("Helvetica", "B", 6.6)
        pdf.cell(cols[2][1], row_h, _risk_label(risk), align="C")

        _tc(pdf, _placement_color(r.placement))
        pdf.set_font("Helvetica", "B", 7.6)
        pdf.cell(cols[3][1], row_h, _placement_label(r.placement))

        _tc(pdf, _BODY)
        pdf.set_font("Helvetica", "", 7.3)
        pdf.cell(cols[4][1], row_h, verdict[:22])
        pdf.cell(cols[5][1], row_h, transforms[:26], new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        _dc(pdf, _LINE)
        pdf.set_line_width(0.15)
        pdf.line(x0, pdf.get_y(), x0 + sum(w for _, w in cols), pdf.get_y())

    # Legend
    pdf.ln(3)
    _tc(pdf, _MUTED)
    pdf.set_font("Helvetica", "", 7.3)
    pdf.set_x(10)
    pdf.multi_cell(190, 4,
        "Delivery: Inbox = reached the user (gateway failure)  -  Junk = quarantined to spam  "
        "-  Blocked = never delivered (best outcome)  -  Inconcl. = not confirmed, excluded from score.  "
        "Gateway verdict: spam category + Microsoft SCL (0-9) when present.  "
        "Transformations: changes the gateway made (URL rewriting, external banner, stripped/proxied content).  "
        "*  = carrier-suspect: sent after the sender's reputation degraded mid-run, so the verdict may reflect "
        "the burned sender rather than the payload.")


# ── Remediation ───────────────────────────────────────────────────────────────

def _remediation(pdf: _PDF, chains: list, results):
    priority = [(r, result_risk(r)) for r in results
                if result_risk(r) in (CRITICAL, HIGH) and r.placement == "INBOX"]
    priority.sort(key=lambda x: RISK_ORDER.get(x[1], 0), reverse=True)

    if not chains and not priority:
        return

    if pdf.get_y() > 235:
        pdf.add_page()
    _section_title(pdf, "Remediation plan", "Prioritized, de-duplicated actions. Start at the top.")

    seen_remeds: set[str] = set()
    priority_num = 1

    if chains:
        _tc(pdf, _INK)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_x(10)
        pdf.cell(0, 5.5, "Actions by detected attack scenario", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

        for entry in chains:
            chain = entry["chain"]
            if pdf.get_y() > 262:
                pdf.add_page()
            color = _risk_color(chain.severity)
            y0 = pdf.get_y()
            _fc(pdf, color)
            pdf.rect(10, y0 + 0.5, 2.6, 5, style="F")
            _tc(pdf, _INK)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_x(15)
            pdf.cell(0, 6, f"{chain.id}  {chain.name}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            for action in chain.remediation:
                if action in seen_remeds:
                    continue
                seen_remeds.add(action)
                if pdf.get_y() > 270:
                    pdf.add_page()
                _tc(pdf, _ACCENT)
                pdf.set_font("Helvetica", "B", 8.5)
                pdf.set_x(15)
                pdf.cell(9, 5, f"P{priority_num}")
                _tc(pdf, _BODY)
                pdf.set_font("Helvetica", "", 8.5)
                pdf.multi_cell(176, 5, action)
                priority_num += 1
            pdf.ln(2)

    if priority:
        if pdf.get_y() > 250:
            pdf.add_page()
        _tc(pdf, _INK)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_x(10)
        pdf.cell(0, 5.5, "Techniques needing immediate attention", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

        for r, risk in priority[:12]:
            if pdf.get_y() > 264:
                pdf.add_page()
            color = _risk_color(risk)
            y0 = pdf.get_y()
            _fc(pdf, _PANEL)
            _dc(pdf, _LINE)
            pdf.set_line_width(0.3)
            pdf.rect(10, y0, 190, 12, style="DF")
            _fc(pdf, color)
            pdf.rect(10, y0, 2.6, 12, style="F")
            _tc(pdf, _INK)
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_xy(15, y0 + 1.5)
            pdf.cell(16, 4, r.technique_id)
            pdf.cell(110, 4, (r.technique_name or "")[:54])
            _risk_badge(pdf, risk, 172, y0 + 1.5, 22, 4.8)
            _tc(pdf, _BODY)
            pdf.set_font("Helvetica", "", 7.8)
            pdf.set_xy(15, y0 + 6)
            pdf.multi_cell(178, 4, (r.threat or "")[:200])
            pdf.set_y(y0 + 12 + 2)


# ── Main entry point ────────────────────────────────────────────────────────────

def generate_report(campaign, results, config=None) -> bytes:
    from .carrier import split_results
    # Canaries are reputation probes, not gateway tests — keep them out of the
    # scoring, chains, findings table and counts; their signal is summarized as a
    # carrier-health note on the cover.
    _canaries, results = split_results(list(results))
    chains  = detect_chains(results)
    demo_mode = any((getattr(r, "validator_id", "") or "").startswith("mock-") for r in results)

    pdf = _PDF(campaign.name)
    pdf.set_auto_page_break(auto=True, margin=14)

    pdf.add_page()
    _cover(pdf, campaign, config, results, chains, demo_mode=demo_mode)

    pdf.add_page()
    _chains_section(pdf, chains)
    _findings_table(pdf, results)
    _remediation(pdf, chains, results)

    return bytes(pdf.output())
