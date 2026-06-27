"""
Shared technique-reference content — the same material as the offline PDF dossier
(scripts/generate_techniques_dossier.py), exposed for the in-app reference page at
/reports/techniques so reviewers can read WHY each technique is sent and WHAT exact
payload it carries without downloading anything.

The PDF keeps its per-technique rationale in Spanish (for the operator); this web
reference is fully English. Hidden evasion characters in payloads (zero-width
spaces, Cyrillic/Greek homoglyphs, HTML entities) are revealed as \\uXXXX so the
trick is visible instead of being silently rendered by the browser.
"""
from app.techniques.registry import load_all, send_rank
from app.techniques.base import RuntimeContext

# Send-order tiers (from registry.SEND_ORDER) — stealthiest payloads first,
# loudest / basic-signature last.
TIERS = {
    "T16": "1 — Content/URL obfuscation & HTML smuggling",
    "T17": "1 — Content/URL obfuscation & HTML smuggling",
    "T29": "1 — Content/URL obfuscation & HTML smuggling",
    "T27": "1 — Content/URL obfuscation & HTML smuggling",
    "T26": "1 — Content/URL obfuscation & HTML smuggling",
    "T06": "1 — Content/URL obfuscation & HTML smuggling",
    "T13": "1 — Content/URL obfuscation & HTML smuggling",
    "T07": "1 — Content/URL obfuscation & HTML smuggling",
    "T14": "1 — Content/URL obfuscation & HTML smuggling",
    "T01": "1 — Content/URL obfuscation & HTML smuggling",
    "T24": "1 — Content/URL obfuscation & HTML smuggling",
    "T22": "1 — Content/URL obfuscation & HTML smuggling",
    "T11": "1 — Content/URL obfuscation & HTML smuggling",
    "T12": "2 — Identity / behaviour (spoof, BEC, QR, calendar)",
    "T23": "2 — Identity / behaviour (spoof, BEC, QR, calendar)",
    "T28": "2 — Identity / behaviour (spoof, BEC, QR, calendar)",
    "T08": "2 — Identity / behaviour (spoof, BEC, QR, calendar)",
    "T18": "3a — Evasive attachments",
    "T03": "3a — Evasive attachments",
    "T02": "3a — Evasive attachments",
    "T04": "3a — Evasive attachments",
    "T15": "3a — Evasive attachments",
    "T20": "3b — Alternative-format malware",
    "T21": "3b — Alternative-format malware",
    "T19": "3b — Alternative-format malware",
    "T25": "3b — Alternative-format malware",
    "T10": "4 — Known-bad URL reputation / macro / EICAR signature",
    "T05": "4 — Known-bad URL reputation / macro / EICAR signature",
    "T09": "4 — Known-bad URL reputation / macro / EICAR signature",
}

# Extended rationale, English. Each entry expands the technique's threat: what the
# evasion is, how it works, and which gateway control / analysis layer it probes.
# Falls back to the technique's short meta.threat if missing.
RATIONALE_EN = {
    "T01": (
        "The HTML body is sent Base64-encoded instead of as clear text. Many gateways run "
        "lexical analysis (regex, signatures, brand and link detection) directly over the HTML; "
        "if the content travels as Base64, that surface-level inspection finds nothing until the "
        "mail client decodes and renders it. This measures whether the gateway decodes Base64 "
        "parts before analysing them, or stops at the plain-text inspection and lets phishing "
        "through 'hidden' in plain sight."
    ),
    "T02": (
        "A phishing HTML file is attached inside a ZIP. The goal is to evade attachment "
        "inspection: some gateways do not unpack ZIP containers to analyse what is inside, so the "
        "malicious HTML passes the filter. On opening, the victim extracts and runs the HTML in "
        "their browser, outside the gateway's control. This tests whether the attachment engine "
        "inspects the inside of compressed archives."
    ),
    "T03": (
        "A phishing .html file is attached directly. When the victim opens it, it renders locally "
        "in their browser from disk (file:// origin), so the gateway — which only saw an "
        "attachment — does not intervene at click time, and URL filters / Safe Links do not apply "
        "to a locally-served page. This tests whether the gateway blocks or neutralises HTML "
        "attachments, a classic credential-theft vector."
    ),
    "T04": (
        "An SVG vector image containing JavaScript is attached. SVG is not an inert image: it is "
        "XML the browser executes, so it can run scripts (XSS, redirection, data theft) when "
        "opened. Many filters treat .svg as harmless images and do not inspect their script. This "
        "tests whether the gateway detects and blocks SVGs with active content."
    ),
    "T05": (
        "A macro-enabled Word document (.docm), the classic Office-macro malware delivery vector. "
        "Even though Microsoft now blocks macros from internet-downloaded files by default, this "
        "remains an essential test: it measures whether the gateway detects and blocks/cleans "
        "macro-enabled documents before they reach the mailbox. It is a 'loud' technique (very "
        "well-known signature), which is why it is sent near the end."
    ),
    "T06": (
        "Zero-width characters (U+200B) are inserted inside URLs and brand names. To the user the "
        "link looks and works the same, but for the gateway engine the string is 'broken' and its "
        "domain/brand-detection regexes no longer match. This tests whether the gateway normalises "
        "(strips invisible characters) before analysing URLs, or whether a simple invisible-Unicode "
        "insertion is enough to evade lexical detection."
    ),
    "T07": (
        "Uses the HTML <base> tag to split the malicious URL in two: the gateway analyses only the "
        "relative fragment (e.g. '/t07', harmless) while the mail client combines <base> + fragment "
        "and resolves the full, malicious URL. This is the 'baseStriker' technique, which evaded "
        "several leading gateways. It tests whether the link analyser resolves <base> the same way "
        "the client does."
    ),
    "T08": (
        "A calendar invitation (.ics). These invites are often added automatically to the user's "
        "calendar and carry URLs and text many gateways do not inspect with the same rigour as a "
        "normal email. This tests whether the gateway parses .ics content and applies reputation / "
        "Safe Links to the links inside."
    ),
    "T09": (
        "Attaches the EICAR test file, the industry-standard probe for confirming an antivirus is "
        "active (not real malware, but every AV engine must detect it). It is the most basic, "
        "direct check: if EICAR reaches the mailbox, the gateway's antivirus is not scanning "
        "attachments. Because it is a 100%-known signature it is the 'loudest' technique, and is "
        "sent last so it doesn't poison the sender's reputation during the rest of the run."
    ),
    "T10": (
        "Instead of attaching EICAR, it links to it (eicar.org). This does not test attachment AV "
        "but URL reputation and analysis: the gateway should recognise the link leads to "
        "AV-detectable content and block or rewrite it. This tests the URL-reputation layer and "
        "link detonation (Safe Links / time-of-click)."
    ),
    "T11": (
        "The email loads images from an external server (hotlinking). Those remote images enable "
        "tracking beacons (confirming the email was opened, the IP, the client) and data "
        "exfiltration via URL parameters. The gateway should block or proxy external images to "
        "prevent beaconing. This tests remote-image handling (Layer 5)."
    ),
    "T12": (
        "The sender's display name impersonates a trusted brand (e.g. 'PayPal Security Team') even "
        "though the real domain is different. Most users only look at the name, not the address. We "
        "keep the real authenticated address (so the provider doesn't reject the send) and only "
        "spoof the display name — exactly what a real attacker does. This tests whether the gateway "
        "/ anti-phishing detects the impersonation and warns the user (banner or quarantine)."
    ),
    "T13": (
        "The URL uses Unicode characters visually identical to Latin letters (Cyrillic or Greek) — "
        "for example the Cyrillic letter U+0430, identical to the Latin 'a', inside 'paypal.com'. "
        "To the human eye the URL looks legitimate, but it is a different domain, and it evades "
        "ASCII-string-based reputation. This tests whether the gateway does normalisation / "
        "punycode and detects homoglyph domains (IDN attack)."
    ),
    "T14": (
        "A URL is included as plain text, without an <a> tag. Some gateways only analyse links that "
        "appear in href attributes and overlook literal URLs written in the text, which the mail "
        "client autolinks anyway and the user can copy. This tests whether link analysis also "
        "covers plain-text URLs."
    ),
    "T15": (
        "'Polyglot' content: valid as several MIME types at once, with scripts hidden in HTML "
        "comments that some gateway parsers do not inspect. It exploits format ambiguity so the "
        "analyser interprets the file one (harmless) way and the client another (executable) way. "
        "This tests the robustness of the gateway parser against deliberately ambiguous content."
    ),
    "T16": (
        "An HTML attachment that, when opened, builds and auto-downloads an executable in the "
        "browser using JavaScript's Blob API ('HTML smuggling'). The malicious file never crosses "
        "the gateway as a standalone attachment: it is assembled locally on the victim's machine "
        "from embedded data. This tests whether the gateway detects the smuggling pattern inside "
        "the HTML rather than only looking for attached files."
    ),
    "T17": (
        "A smuggling variant: instead of attaching the HTML, it links to a page (hosted on "
        "infrastructure you control) that generates and delivers the payload via Blob API in the "
        "victim's browser. The gateway only sees a URL; the file is created entirely on the client. "
        "This tests whether URL reputation / detonation detects smuggling pages. Requires "
        "configuring your server under Settings → Payload hosting."
    ),
    "T18": (
        "A password-encrypted ZIP (traditional PKZIP encryption) with the password written in the "
        "email body. The gateway cannot decrypt or scan the content, but the user can open it with "
        "the supplied key. This is a very active vector in ransomware campaigns. It tests how the "
        "gateway handles encrypted attachments it cannot inspect: does it block them, flag them, or "
        "let them through?"
    ),
    "T19": (
        "A .iso disk image. Windows 10+ mounts .iso files on double-click, with no need to extract "
        "them, and many gateways do not inspect the internal content of disk images. It was the "
        "dominant Emotet/Qakbot vector in 2021-2022 for exactly that reason. This tests whether the "
        "gateway analyses the inside of .iso containers."
    ),
    "T20": (
        "A OneNote (.one) file, which can embed clickable executables and scripts. It surged as a "
        "vector in 2022-2023 when Microsoft blocked Office macros by default, and many gateways do "
        "not fully parse the OneNote format. This tests whether the gateway understands and "
        "analyses .one attachments."
    ),
    "T21": (
        "A PDF with a JavaScript action (OpenAction) that runs when the document is opened, with no "
        "user interaction. The gateway must detect and block JS embedded in PDFs. This tests deep "
        "PDF inspection, not just reputation or file extension."
    ),
    "T22": (
        "The link is routed through an open redirector on a maximum-reputation domain "
        "(google.com/url?q=...) to disguise the real destination. The gateway sees 'google.com' "
        "(trusted) and may not follow the redirect chain to the malicious destination. This tests "
        "whether URL analysis follows redirects on trusted domains instead of trusting the first hop."
    ),
    "T23": (
        "The From shows an apparently legitimate domain but the Reply-To points to an attacker's "
        "domain: when the victim replies, their reply goes to the attacker. This is the core of BEC "
        "(Business Email Compromise / CEO fraud). This tests whether the gateway detects the "
        "From / Reply-To mismatch and flags it as suspicious."
    ),
    "T24": (
        "An HTML file is sent declared as Content-Type: image/gif. Gateways that trust the declared "
        "MIME type without verifying the content's real 'magic bytes' will not analyse the HTML or "
        "its JavaScript, believing it is a harmless image. This tests whether the gateway validates "
        "the real content against the declared type."
    ),
    "T25": (
        "A Windows shortcut (.lnk) with command-line arguments that run arbitrary commands, packed "
        "in a ZIP to dodge filters on directly-attached .lnk files. Very common after the macro "
        "block. This tests whether the gateway inspects the inside of the ZIP and detects the "
        "dangerous .lnk."
    ),
    "T26": (
        "The URL is encoded as HTML entities (&#x68;&#x74;&#x74;&#x70;...). URL parsers that do not "
        "decode entities before analysing detect no link at all. This tests whether the gateway "
        "decodes HTML entities before its link analysis."
    ),
    "T27": (
        "The href attribute is empty; JavaScript assembles the real URL from data-* attributes on "
        "click. Static scanners find no URL in the HTML because it only exists at runtime. This "
        "tests whether the gateway detects dynamically-constructed links or only static ones."
    ),
    "T28": (
        "The malicious URL is encoded into an embedded QR-code image in the body ('quishing'). "
        "Gateways do not OCR or read QR codes, so no URL-reputation engine detects the link; the "
        "victim scans it with their phone, often outside the corporate perimeter. This tests "
        "whether the gateway analyses QR-image content. Requires configuring your server under "
        "Settings → Payload hosting."
    ),
    "T29": (
        "A link to an AV-detectable payload (EICAR) hosted on Azure Blob / AWS S3. Because the URL "
        "lives on a Microsoft/Amazon domain that proxies, VPN allowlists and category filters treat "
        "as trusted, reputation-based controls are usually evaded ('living off trusted sites'). "
        "This tests whether the gateway inspects the real content hosted on trusted clouds instead "
        "of trusting the domain. Requires configuring the URL under Settings → Payload hosting."
    ),
}

# Map a few typographic characters to ASCII for readability; everything else
# non-ASCII is revealed as \uXXXX so hidden evasion characters are visible.
_TYPO = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", "→": "->",
}


def reveal(s: str, limit: int = 4000) -> str:
    """Return an ASCII-safe rendering that exposes non-ASCII / hidden chars as
    \\uXXXX. Used for PAYLOAD content, where hidden evasion characters must be
    visible (zero-width spaces, homoglyphs). HTML special chars are left as-is —
    Jinja2 autoescaping renders them safely as text in the template."""
    out = []
    for ch in s:
        if ch in "\n\t":
            out.append(ch)
            continue
        o = ord(ch)
        if 32 <= o < 127:
            out.append(ch)
        elif ch in _TYPO:
            out.append(_TYPO[ch])
        else:
            out.append(f"\\u{o:04x}")
    text = "".join(out)
    if len(text) > limit:
        text = text[:limit] + "\n... [truncated]"
    return text


def _part_body(part):
    """Decode a MIME part for display. Returns (kind, text) where kind is
    'text' (show content) or 'binary' (show metadata + magic bytes)."""
    try:
        raw = part.get_payload(decode=True) or b""
    except Exception:
        raw = b""
    ct = part.get_content_type()
    text_like = ct.startswith("text/") or ct in (
        "application/svg+xml", "application/html",
    ) or (part.get_filename() or "").lower().endswith((".ics", ".com", ".svg", ".html", ".htm"))
    if text_like:
        try:
            return "text", raw.decode("utf-8", errors="replace")
        except Exception:
            pass
    head = " ".join(f"{b:02x}" for b in raw[:24])
    return "binary", f"[binary, {len(raw)} bytes]  magic: {head}"


def build_reference():
    """Return a list of per-technique dicts (id, name, tier, rank, rationale,
    requirements, payload) for the in-app reference page. Hidden characters in
    payloads are revealed; mirror of the offline PDF dossier, fully English."""
    ctx = RuntimeContext(
        web_base_url="https://payload.example.com",
        cloud_payload_url="https://acct.blob.core.windows.net/files/document.html",
    )
    items = []
    for t in load_all():
        m = t.meta

        reqs = []
        if m.expected_attachments:
            reqs.append(f"Expected attachment(s): {', '.join(m.expected_attachments)}")
        if m.expected_images:
            reqs.append("Expects external/inline images")
        if m.spoof_from_name:
            reqs.append(f'Spoofed From display name: "{m.spoof_from_name}"')
        if m.requires:
            reqs.append(f"Requires deploy config: {m.requires} (hosted payload infrastructure)")

        payload = {"subject": None, "headers": [], "parts": [], "error": None}
        try:
            msg = t.render(ctx)
            payload["subject"] = reveal(str(msg.get("Subject") or ""))
            for extra in ("Reply-To", "From"):
                if msg.get(extra):
                    payload["headers"].append((extra, reveal(str(msg.get(extra)))))
            parts = list(msg.walk()) if msg.is_multipart() else [msg]
            for part in parts:
                if part.is_multipart():
                    continue
                ct = part.get_content_type()
                fn = part.get_filename()
                cte = part.get("Content-Transfer-Encoding")
                kind, content = _part_body(part)
                payload["parts"].append({
                    "content_type": ct,
                    "filename": fn,
                    "cte": cte,
                    "kind": kind,
                    "content": reveal(content),
                })
        except Exception as e:  # never let one bad render break the whole page
            payload["error"] = f"[could not render payload: {e}]"

        items.append({
            "id": m.id,
            "name": m.name,
            "tier": TIERS.get(m.id, "—"),
            "rank": send_rank(m.id),
            "rationale": RATIONALE_EN.get(m.id, m.threat),
            "requirements": reqs,
            "payload": payload,
        })
    return items
