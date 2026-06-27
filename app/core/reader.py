"""
IMAP-based multi-layer email analyzer.

Paradigm: server-side only. No beacons, no tracking pixels, no client opens needed.
The reader connects to the mailbox, finds each sent message by its validator_id,
and runs a 5-layer analysis on what actually arrived vs what was sent.
"""

from __future__ import annotations

import email
import imaplib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Callable, Optional

# ── Delivery-wait strategy (seconds, overridable via env) ─────────────────────
# Two-phase polling: wait (possibly long) for the FIRST message to land, then
# keep polling and marking each arrival until a quiet period passes with no new
# messages, or the absolute cap is hit.
FIRST_TIMEOUT    = int(os.getenv("READ_FIRST_TIMEOUT",    "600"))   # max wait for the 1st
QUIET_PERIOD     = int(os.getenv("READ_QUIET_PERIOD",     "180"))   # idle window after last arrival
POLL_INTERVAL    = int(os.getenv("READ_POLL_INTERVAL",    "15"))
ABSOLUTE_TIMEOUT = int(os.getenv("READ_ABSOLUTE_TIMEOUT", "1800"))  # hard cap for the whole wait

# ── URL rewriting patterns used by known gateways ────────────────────────────
_REWRITE_PATTERNS = [
    r"safelinks\.protection\.outlook\.com",   # Microsoft Defender
    r"urldefense(?:pro)?\.com",               # Proofpoint
    r"urldefense\.proofpoint\.com",
    r"google\.com/url\?",                     # Google Workspace
    r"symanteccloud\.com",                    # Symantec
    r"mimecastprotect\.com",                  # Mimecast
]

# ── Warning banner markers injected into body by gateways ────────────────────
_BANNER_MARKERS = [
    "ExternalClass",                 # Outlook external-sender banner
    "x_outercontainer",
    "external-email-warning",
    "caution-external",
    "este correo proviene de fuera",
    "this email came from outside",
    "be cautious with this email",
    "x-ms-exchange-organization",    # Sometimes leaked into HTML wrappers
]


@dataclass
class LayeredAnalysis:
    # ── Layer 1: delivery ─────────────────────────────────────────────────────
    found: bool = False
    placement: str = "MISSING"          # INBOX | JUNK | MISSING

    # ── Layer 2: gateway verdict ──────────────────────────────────────────────
    scl: Optional[int] = None           # Microsoft SCL 0-9  (-1 = whitelisted)
    gateway_category: Optional[str] = None  # PHSH | MALW | BULK | SPOOF | NONE
    spf: Optional[str] = None           # pass | fail | softfail | neutral | none
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    gateway_raw: dict = field(default_factory=dict)

    # ── Layer 3: body transformations ─────────────────────────────────────────
    links_rewritten: bool = False       # Safe Links / URL rewriter detected
    banner_injected: bool = False       # External-sender warning injected
    body_modified: bool = False         # Any other modification

    # ── Layer 4: attachments ──────────────────────────────────────────────────
    attachments_received: list[str] = field(default_factory=list)
    attachments_stripped: bool = False  # At least one expected attachment did not arrive

    # ── Layer 5: images ───────────────────────────────────────────────────────
    images_present: bool = False        # At least one <img> or image/* part found
    images_stripped: bool = False       # Images were expected but did not arrive
    images_proxied: bool = False        # Image URLs rewritten by the gateway

    # ── Meta ──────────────────────────────────────────────────────────────────
    message_id: Optional[str] = None
    delivered_at: Optional[datetime] = None
    error: Optional[str] = None         # Description if a technical problem occurred


@dataclass
class AnalysisItem:
    """One message to wait for and analyse."""
    validator_id: str
    expected_attachments: list[str] = field(default_factory=list)
    expected_images: bool = False


class MailReader(ABC):
    @abstractmethod
    def analyze(
        self,
        validator_id: str,
        expected_attachments: list[str],
        expected_images: bool,
    ) -> LayeredAnalysis:
        ...


class IMAPReader(MailReader):
    """
    Reads and analyzes emails from an IMAP mailbox.
    Searches all relevant folders (INBOX + Junk variants) without requiring
    the email to be opened by any client.
    """

    # Folder names → placement label mappings (case-insensitive)
    _JUNK_NAMES = {
        "junk", "junk email", "junk mail",
        "spam", "bulk mail", "bulk",
        "[gmail]/spam",
    }

    # How long (seconds) to wait between retries when message not yet found
    _RETRY_INTERVAL = 15
    _MAX_RETRIES    = 4   # total wait = 15 × 4 = 60s after initial attempt

    def __init__(self, host: str, port: int, user: str, password: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    def test_connection(self) -> tuple[bool, str]:
        if not (self.host and self.user and self.password):
            return False, "IMAP host, user and password are required."
        try:
            with imaplib.IMAP4_SSL(self.host, self.port) as imap:
                imap.login(self.user, self.password)
                imap.select("INBOX", readonly=True)
            return True, f"Connected to {self.host} and opened INBOX as {self.user}."
        except Exception as exc:
            return False, f"IMAP error: {exc}"

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        validator_id: str,
        expected_attachments: list[str] | None = None,
        expected_images: bool = False,
    ) -> LayeredAnalysis:
        result = LayeredAnalysis()
        try:
            with imaplib.IMAP4_SSL(self.host, self.port) as imap:
                imap.login(self.user, self.password)
                folders = self._discover_folders(imap)

                # Retry loop: EOP / Outlook can take a few seconds to classify and deliver
                for attempt in range(self._MAX_RETRIES + 1):
                    for folder_name, placement in folders:
                        msg = self._find_message(imap, folder_name, validator_id)
                        if msg is None:
                            continue

                        result = build_analysis(
                            msg, placement,
                            expected_attachments or [], expected_images,
                        )
                        break

                    if result.found:
                        break
                    if attempt < self._MAX_RETRIES:
                        time.sleep(self._RETRY_INTERVAL)

        except imaplib.IMAP4.error as exc:
            result.error = f"IMAP error: {exc}"
        except Exception as exc:
            result.error = f"Unexpected error: {exc}"

        return result

    # ── Batch two-phase wait ──────────────────────────────────────────────────

    def wait_and_analyze(
        self,
        items: list[AnalysisItem],
        persist: Callable[[str, LayeredAnalysis], None],
        *,
        first_timeout: int = FIRST_TIMEOUT,
        quiet_period: int = QUIET_PERIOD,
        poll_interval: int = POLL_INTERVAL,
        absolute_timeout: int = ABSOLUTE_TIMEOUT,
        since: "Optional[str]" = None,   # accepted for interface parity (Graph uses it)
    ) -> None:
        """
        Poll a single IMAP session for every item until resolved.

        Phase 1 — wait up to `first_timeout` for the FIRST message to appear in
                  any folder.
        Phase 2 — once at least one has arrived, keep polling and resolving each
                  arrival, calling `persist(validator_id, analysis)` immediately so
                  the UI can refresh live, until `quiet_period` elapses with no new
                  message (or `absolute_timeout` is hit).

        Final classification of anything still missing:
          • at least one arrived  → MISSING  (pipeline works, this one was blocked)
          • nothing ever arrived  → NOT_FOUND (inconclusive: delivery/IMAP issue)
        """
        remaining: dict[str, AnalysisItem] = {it.validator_id: it for it in items}
        if not remaining:
            return

        any_arrived = False
        start = time.monotonic()
        last_arrival = start

        try:
            with imaplib.IMAP4_SSL(self.host, self.port) as imap:
                imap.login(self.user, self.password)
                folders = self._discover_folders(imap)

                while remaining:
                    for vid in list(remaining):
                        item = remaining[vid]
                        msg, placement = self._find_in_folders(imap, folders, vid)
                        if msg is None:
                            continue
                        analysis = self._extract_analysis(
                            msg, placement,
                            item.expected_attachments, item.expected_images,
                        )
                        persist(vid, analysis)
                        remaining.pop(vid, None)
                        any_arrived = True
                        last_arrival = time.monotonic()

                    if not remaining:
                        break

                    now = time.monotonic()
                    if now - start >= absolute_timeout:
                        break
                    if not any_arrived:
                        if now - start >= first_timeout:
                            break
                    elif now - last_arrival >= quiet_period:
                        break

                    time.sleep(poll_interval)

        except imaplib.IMAP4.error as exc:
            self._flush_unresolved(remaining, persist, error=f"IMAP error: {exc}")
            return
        except Exception as exc:
            self._flush_unresolved(remaining, persist, error=f"Unexpected error: {exc}")
            return

        # Conclusive run: classify whatever never showed up.
        for vid, item in remaining.items():
            analysis = LayeredAnalysis()
            analysis.placement = "MISSING" if any_arrived else "NOT_FOUND"
            persist(vid, analysis)

    @staticmethod
    def _flush_unresolved(remaining, persist, error: str) -> None:
        """Connection-level failure → everything left is inconclusive."""
        for vid in list(remaining):
            analysis = LayeredAnalysis()
            analysis.placement = "NOT_FOUND"
            analysis.error = error
            persist(vid, analysis)

    def _find_in_folders(self, imap, folders, validator_id):
        for folder_name, placement in folders:
            msg = self._find_message(imap, folder_name, validator_id)
            if msg is not None:
                return msg, placement
        return None, None

    def _extract_analysis(
        self, msg, placement: str,
        expected_attachments: list[str], expected_images: bool,
    ) -> LayeredAnalysis:
        return build_analysis(msg, placement, expected_attachments or [], expected_images)

    # ── Folder discovery ──────────────────────────────────────────────────────

    def _discover_folders(self, imap: imaplib.IMAP4_SSL) -> list[tuple[str, str]]:
        """Return [(folder_name, placement_label)] ordered: INBOX first, then Junk variants."""
        folders: list[tuple[str, str]] = [("INBOX", "INBOX")]

        _, raw_list = imap.list()
        for entry in raw_list or []:
            if not entry:
                continue
            decoded = entry.decode(errors="ignore")
            name = _parse_imap_folder_name(decoded)
            if name and name.lower() in self._JUNK_NAMES:
                folders.append((name, "JUNK"))

        return folders

    # ── Message search ────────────────────────────────────────────────────────

    def _find_message(
        self, imap: imaplib.IMAP4_SSL, folder: str, validator_id: str
    ) -> email.message.Message | None:
        try:
            imap.select(f'"{folder}"', readonly=True)
        except imaplib.IMAP4.error:
            try:
                imap.select(folder, readonly=True)
            except imaplib.IMAP4.error:
                return None

        # Locate strictly by the X-Validator-ID header. RFC 3501 mandates SEARCH
        # HEADER support (Gmail, Outlook, Dovecot all honor it), and keeping the
        # token out of the subject lets the subject stay natural.
        try:
            _, data = imap.search(None, f'HEADER X-Validator-ID "{validator_id}"')
            ids = (data[0] or b"").split()
        except imaplib.IMAP4.error:
            ids = []

        if not ids:
            return None

        _, msg_data = imap.fetch(ids[-1], "(RFC822)")
        if not msg_data or not msg_data[0]:
            return None

        raw = msg_data[0][1]
        return email.message_from_bytes(raw) if isinstance(raw, bytes) else None


# ── Shared multi-layer analysis (provider-independent) ─────────────────────────
# Both IMAPReader and GraphAPIReader feed a parsed email.message.Message here, so
# the 5-layer analysis is written once and reused regardless of how the raw MIME
# was fetched (IMAP RFC822 or Graph /$value).

def build_analysis(
    msg: email.message.Message,
    placement: str,
    expected_attachments: list[str],
    expected_images: bool,
) -> LayeredAnalysis:
    result = LayeredAnalysis()
    result.found = True
    result.placement = placement
    result.message_id = msg.get("Message-ID")
    result.delivered_at = _parse_date(msg.get("Date"))
    _layer2_gateway_headers(msg, result)
    _layer3_body(msg, result)
    _layer45_payload(msg, result, expected_attachments or [], expected_images)
    return result


# ── Layer 2: gateway headers ──────────────────────────────────────────────────

def _layer2_gateway_headers(msg: email.message.Message, result: LayeredAnalysis):
    headers = dict(msg.items())
    result.gateway_raw = {
        k: v for k, v in headers.items()
        if any(k.lower().startswith(p) for p in (
            "x-microsoft", "x-forefront", "x-ms-exchange",
            "x-gm-", "x-proofpoint", "x-mimecast",
            "authentication-results", "received-spf",
        ))
    }

    # Microsoft SCL
    scl_raw = headers.get("X-MS-Exchange-Organization-SCL")
    if scl_raw:
        try:
            result.scl = int(scl_raw.strip())
        except ValueError:
            pass

    # Microsoft gateway category from X-Forefront-Antispam-Report
    # CAT:PHSH | MALW | BULK | SPOOF | NONE | SPM | HPHSH
    forefront = headers.get("X-Forefront-Antispam-Report", "")
    cat = re.search(r"CAT:([A-Z]+)", forefront)
    if cat:
        result.gateway_category = cat.group(1)

    # SPF / DKIM / DMARC — parse Authentication-Results
    auth = (
        headers.get("Authentication-Results")
        or headers.get("Authentication-Results-Original")
        or headers.get("ARC-Authentication-Results")
        or ""
    )
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{proto}=(\w+)", auth, re.IGNORECASE)
        if m:
            setattr(result, proto, m.group(1).lower())


# ── Layer 3: body transformations ─────────────────────────────────────────────

def _layer3_body(msg: email.message.Message, result: LayeredAnalysis):
    body = _extract_body(msg)
    if not body:
        return

    # Safe Links / URL rewriting
    for pattern in _REWRITE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            result.links_rewritten = True
            break

    # Warning banners injected by gateway
    body_lower = body.lower()
    for marker in _BANNER_MARKERS:
        if marker.lower() in body_lower:
            result.banner_injected = True
            break

    result.body_modified = result.links_rewritten or result.banner_injected


# ── Layer 4 & 5: attachments and images ────────────────────────────────────────

def _layer45_payload(
    msg: email.message.Message,
    result: LayeredAnalysis,
    expected_attachments: list[str],
    expected_images: bool,
):
    received_attachments: list[str] = []
    found_images = False

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = part.get("Content-Disposition", "")

        # Attachments
        if "attachment" in disposition.lower():
            filename = part.get_filename() or "unnamed"
            received_attachments.append(filename)

        # Inline images (image/*)
        if content_type.startswith("image/"):
            found_images = True

        # HTML body — check for <img> and proxy patterns
        if content_type == "text/html":
            html = part.get_payload(decode=True) or b""
            img_srcs = re.findall(rb'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if img_srcs:
                found_images = True
                for src in img_srcs:
                    src_str = src.decode(errors="ignore")
                    for pattern in _REWRITE_PATTERNS:
                        if re.search(pattern, src_str, re.IGNORECASE):
                            result.images_proxied = True
                            break

    result.attachments_received = received_attachments

    if expected_attachments:
        received_lower = [a.lower() for a in received_attachments]
        missing = [
            a for a in expected_attachments
            if not any(a.lower() in r for r in received_lower)
        ]
        result.attachments_stripped = bool(missing)

    result.images_present = found_images
    if expected_images and not found_images:
        result.images_stripped = True


# ── Helpers ───────────────────────────────────────────────────────────────────

# RFC 3501 IMAP LIST line: "* LIST (<flags>) <sep> <name>"
# sep can be "/" or "." and may or may not be quoted.
# name can be quoted ("Junk Email") or unquoted (INBOX).
_IMAP_LIST_RE = re.compile(
    r'^\*?\s*LIST\s+\([^)]*\)\s+(?:"[^"]*"|[^\s]+)\s+(.+)$',
    re.IGNORECASE,
)

def _parse_imap_folder_name(line: str) -> str | None:
    """
    Parse an IMAP LIST response line and return the folder name, or None.
    Handles both quoted and unquoted separators and names (Outlook, Gmail, Exchange).
    """
    m = _IMAP_LIST_RE.match(line.strip())
    if not m:
        # Fallback: take the last token after the separator field
        # e.g. '(\HasNoChildren) "/" "Junk Email"' without leading "* LIST"
        parts = line.rsplit(None, 1)
        name = parts[-1].strip().strip('"') if parts else ""
        return name or None
    return m.group(1).strip().strip('"')


def _extract_body(msg: email.message.Message) -> str:
    """Extract HTML body first, then plain text."""
    for content_type in ("text/html", "text/plain"):
        for part in msg.walk():
            if part.get_content_type() == content_type:
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(errors="ignore")
    return ""


def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


class GraphAPIReader(MailReader):
    """
    Reads and analyzes emails from a Microsoft 365 mailbox via Microsoft Graph,
    using app-only (client-credentials) auth. No interactive login, no IMAP —
    ideal for a self-hosted tool where the deployer is tenant admin.

    Requires an Entra ID app registration with the **Application** permission
    Microsoft Graph › Mail.Read (admin-consented). Recommended: scope the app to
    the single test mailbox with an Exchange Application Access Policy.

    Only the standard library is used (urllib) — no msal/requests dependency.
    """

    _AUTHORITY = "https://login.microsoftonline.com"
    _GRAPH = "https://graph.microsoft.com/v1.0"
    _SCOPE = "https://graph.microsoft.com/.default"

    # well-known folders → placement label
    _FOLDERS = [("inbox", "INBOX"), ("junkemail", "JUNK")]

    _RETRY_INTERVAL = 15
    _MAX_RETRIES = 4

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, mailbox: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.mailbox = mailbox
        self._token: Optional[str] = None
        self._token_exp: float = 0.0

    def test_connection(self) -> tuple[bool, str]:
        if not (self.tenant_id and self.client_id and self.client_secret):
            return False, "Tenant ID, client ID and client secret are required."
        if not self.mailbox:
            return False, "A target mailbox is required."
        try:
            self._get_token()
        except Exception as exc:
            return False, f"Token request failed (check tenant/client/secret): {exc}"
        try:
            mbox = urllib.parse.quote(self.mailbox)
            self._graph_get(f"/users/{mbox}/mailFolders/inbox?$select=id")
            return True, f"Token acquired and mailbox '{self.mailbox}' is readable via Graph."
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode(errors="ignore")[:300]
            except Exception:
                pass
            return False, (
                f"Graph denied access to the mailbox (HTTP {exc.code}). "
                f"Check Mail.Read Application permission + admin consent. {detail}"
            )
        except Exception as exc:
            return False, f"Graph error: {exc}"

    # ── Auth ───────────────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        data = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self._SCOPE,
            "grant_type": "client_credentials",
        }).encode()
        url = f"{self._AUTHORITY}/{self.tenant_id}/oauth2/v2.0/token"
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read())
        self._token = payload["access_token"]
        self._token_exp = time.time() + int(payload.get("expires_in", 3600))
        return self._token

    def _graph_get(self, path: str, raw: bool = False):
        token = self._get_token()
        url = path if path.startswith("http") else f"{self._GRAPH}{path}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        return data if raw else json.loads(data)

    # ── Message search ─────────────────────────────────────────────────────────

    # Safety cap on pagination per folder: ~10 pages × 100 = the 1000 newest
    # messages. Bounds API calls for a busy/reused test mailbox while still
    # tolerating one that accumulates well past a single page.
    _MAX_PAGES = 10

    @staticmethod
    def _header_value(message: dict):
        """Return the message's X-Validator-ID header value, or None."""
        for h in message.get("internetMessageHeaders") or []:
            if (h.get("name") or "").lower() == "x-validator-id":
                return (h.get("value") or "").strip()
        return None

    def _iter_folder(self, mbox: str, folder: str, since: "Optional[str]"):
        """Yield messages from a folder, newest first, following @odata.nextLink.

        Only id + headers + receivedDateTime are selected (cheap). When `since`
        (ISO-8601 UTC) is given, the server filters to messages received on/after
        it — so a reused mailbox that has accumulated thousands of old messages
        is never paged through. A per-folder page cap bounds the worst case."""
        sel = "id,internetMessageHeaders,receivedDateTime"
        if since:
            query = (f"?$select={sel}&$top=100"
                     f"&$filter=receivedDateTime%20ge%20{since}"
                     f"&$orderby=receivedDateTime%20desc")
        else:
            query = f"?$select={sel}&$top=100&$orderby=receivedDateTime%20desc"
        path = f"/users/{mbox}/mailFolders/{folder}/messages{query}"
        pages = 0
        while path and pages < self._MAX_PAGES:
            try:
                data = self._graph_get(path)
            except Exception:
                return
            for m in data.get("value", []):
                yield m
            path = data.get("@odata.nextLink")
            pages += 1

    def _download(self, mbox: str, msg_id: str):
        """Download a message's raw MIME, or None if it can't be fetched.

        Some item types (e.g. calendar invites) return HTTP 500 on /$value;
        callers fall back to delivery-only (placement known, body unavailable)."""
        try:
            raw = self._graph_get(f"/users/{mbox}/messages/{msg_id}/$value", raw=True)
        except Exception:
            return None
        return email.message_from_bytes(raw) if isinstance(raw, bytes) else None

    def _scan(self, vids, since: "Optional[str]" = None) -> dict:
        """One pass over all folders, matching MANY validator IDs at once.

        Lists each folder once (paginated) and matches every wanted X-Validator-ID
        against that single response set, instead of re-listing per ID. This cuts
        Graph calls ~Nx for an N-message campaign and avoids the throttling that
        a per-ID re-listing pattern triggers. Returns {vid: (msg|None, placement)}
        for every located vid; msg is None when located but the body failed to
        download. Inbox takes precedence over Junk (folder order)."""
        wanted = set(vids)
        found: dict = {}
        if not wanted:
            return found
        mbox = urllib.parse.quote(self.mailbox)
        for folder, placement in self._FOLDERS:
            for m in self._iter_folder(mbox, folder, since):
                vid = self._header_value(m)
                if vid and vid in wanted and vid not in found:
                    found[vid] = (self._download(mbox, m.get("id")), placement)
                    if len(found) == len(wanted):
                        return found
        return found

    def _find_message(self, validator_id: str):
        """Locate a single message. Returns (msg, placement), (None, placement)
        if located but body unavailable, or (None, None) if not found."""
        return self._scan({validator_id}).get(validator_id, (None, None))

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(
        self,
        validator_id: str,
        expected_attachments: list[str] | None = None,
        expected_images: bool = False,
    ) -> LayeredAnalysis:
        result = LayeredAnalysis()
        try:
            for attempt in range(self._MAX_RETRIES + 1):
                msg, placement = self._find_message(validator_id)
                if msg is not None:
                    return build_analysis(
                        msg, placement, expected_attachments or [], expected_images
                    )
                if placement is not None:
                    # Located but body unavailable — report delivery only.
                    result.found = True
                    result.placement = placement
                    result.error = "Body unavailable (Graph /$value failed)"
                    return result
                if attempt < self._MAX_RETRIES:
                    time.sleep(self._RETRY_INTERVAL)
        except Exception as exc:
            result.error = f"Graph error: {exc}"
        return result

    def wait_and_analyze(
        self,
        items: list[AnalysisItem],
        persist: Callable[[str, LayeredAnalysis], None],
        *,
        first_timeout: int = FIRST_TIMEOUT,
        quiet_period: int = QUIET_PERIOD,
        poll_interval: int = POLL_INTERVAL,
        absolute_timeout: int = ABSOLUTE_TIMEOUT,
        since: "Optional[str]" = None,
    ) -> None:
        """Two-phase polling over Graph, mirroring IMAPReader.wait_and_analyze.

        Each poll scans the folders ONCE for all still-missing IDs (see _scan),
        rather than re-listing per message — far fewer Graph calls, no throttling.
        `since` (ISO-8601 UTC) confines the search to recent messages."""
        remaining: dict[str, AnalysisItem] = {it.validator_id: it for it in items}
        if not remaining:
            return

        any_arrived = False
        start = time.monotonic()
        last_arrival = start

        # Fail fast if auth/permissions are misconfigured (let it propagate so
        # the worker logs it and leaves rows NOT_FOUND).
        self._get_token()

        while remaining:
            # One folder-listing pass for every remaining ID. A transient error
            # is swallowed by _scan/_iter_folder, so a single bad message or a
            # throttled call never aborts the read — it just retries next poll.
            try:
                found = self._scan(set(remaining), since)
            except Exception:
                found = {}
            for vid, (msg, placement) in found.items():
                item = remaining.get(vid)
                if item is None:
                    continue
                if msg is not None:
                    analysis = build_analysis(
                        msg, placement,
                        item.expected_attachments, item.expected_images,
                    )
                else:
                    # Located in a folder but body unavailable — record delivery.
                    analysis = LayeredAnalysis()
                    analysis.found = True
                    analysis.placement = placement
                    analysis.error = "Body unavailable (Graph /$value failed)"
                persist(vid, analysis)
                remaining.pop(vid, None)
                any_arrived = True
                last_arrival = time.monotonic()

            if not remaining:
                break

            now = time.monotonic()
            if now - start >= absolute_timeout:
                break
            if not any_arrived:
                if now - start >= first_timeout:
                    break
            elif now - last_arrival >= quiet_period:
                break

            time.sleep(poll_interval)

        for vid in remaining:
            analysis = LayeredAnalysis()
            analysis.placement = "MISSING" if any_arrived else "NOT_FOUND"
            persist(vid, analysis)


class GmailAPIReader(MailReader):
    """
    Placeholder for Google Workspace (Gmail API + service account with
    domain-wide delegation). Not yet implemented — selecting the Google backend
    surfaces a clear error instead of silently failing.
    """

    def __init__(self, sa_json: str, mailbox: str):
        self.sa_json = sa_json
        self.mailbox = mailbox

    _MSG = ("Google backend (Gmail API) is not implemented yet. "
            "Use IMAP or Microsoft Graph for now.")

    def test_connection(self) -> tuple[bool, str]:
        return False, self._MSG

    def analyze(self, validator_id, expected_attachments=None, expected_images=False):
        result = LayeredAnalysis()
        result.placement = "NOT_FOUND"
        result.error = self._MSG
        return result

    def wait_and_analyze(self, items, persist, **kwargs) -> None:
        for it in items:
            analysis = LayeredAnalysis()
            analysis.placement = "NOT_FOUND"
            analysis.error = self._MSG
            persist(it.validator_id, analysis)


def reader_from_config(config) -> MailReader:
    """Convenience factory from a Config ORM object, dispatching on reader_backend."""
    backend = (getattr(config, "reader_backend", None) or "imap").lower()

    if backend == "microsoft":
        return GraphAPIReader(
            tenant_id=config.ms_tenant_id,
            client_id=config.ms_client_id,
            client_secret=config.ms_client_secret,
            mailbox=config.target_email,
        )
    if backend == "google":
        return GmailAPIReader(
            sa_json=config.google_sa_json,
            mailbox=config.target_email,
        )
    return IMAPReader(
        host=config.imap_host,
        port=config.imap_port,
        user=config.imap_user,
        password=config.imap_pass,
    )
