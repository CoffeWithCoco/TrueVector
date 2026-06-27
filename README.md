# TrueVector — Email Attack Surface Validator

> Self-hosted tool that measures how effective your email gateway really is.

TrueVector sends a battery of **29 controlled evasion techniques** (HTML smuggling,
ZIP/ISO/LNK attachments, Office macros, EICAR, display-name spoofing, BEC, QR
phishing, …) to a test mailbox **you own**, then **reads them back** via IMAP or
the Microsoft Graph API and runs a **5-layer analysis** to classify what arrived,
where (Inbox / Junk / blocked) and how the gateway transformed it.

No beacons, no tracking pixels, no client interaction — everything is **server-side
analysis** of what actually landed in the mailbox.

It is GoPhish-like in form, but the goal is different: instead of phishing users, it
**audits the gateway's controls** (Microsoft Defender/EOP, Proofpoint, Mimecast,
Google Workspace, …) so the deployer — who is the admin of the target tenant — can
see exactly which threats slip through.

---

## ⚠️ Authorized use only

This tool sends content that includes the EICAR test file, macro-enabled documents,
disk-image/shortcut attachments and phishing-style payloads. **Use it only against
mailboxes and tenants you own or are explicitly authorized to test.**

- The payloads are inert (no real malware), but mail providers may flag or suspend a
  sending account that emits them — use a dedicated test account.
- You are responsible for complying with the acceptable-use policies of every
  provider and network involved.
- The authors accept no liability for misuse. See [SECURITY.md](SECURITY.md).

---

## Features

- **29 evasion techniques** spanning content obfuscation, malicious attachments,
  URL evasion, spoofing/BEC, HTML smuggling and trusted-cloud delivery — each one a
  real, inspectable email.
- **5-layer analysis** of every message that arrives:
  1. **Delivery** — Inbox / Junk / blocked
  2. **Gateway verdict** — SCL, antispam category, SPF/DKIM/DMARC
  3. **Body transformations** — Safe Links/URL rewriting, external-sender banners
  4. **Attachments** — stripped vs intact
  5. **Images** — stripped / proxied / intact
- **Two mailbox-reader backends**: IMAP, or **Microsoft Graph (app-only)** for M365
  tenants where IMAP basic auth is disabled. Google Workspace is stubbed for now.
- **Protection score** + **MITRE ATT&CK attack-chain detection** with a prioritized
  remediation plan.
- **Executive PDF report**.
- **Built-in connection tester** for SMTP + mailbox reader before launching.
- **Demo mode** when no SMTP/mailbox is configured (clearly labelled simulated data).
- Single-file dependencies, SQLite storage, one-command Docker deploy.

## Tech stack

FastAPI · Jinja2 · HTMX · SQLAlchemy · SQLite · fpdf2 · Docker. The Microsoft Graph
backend uses only the Python standard library (`urllib`) — no extra dependency.

---

## Deployment

```bash
cp .env.example .env        # optional: adjust variables
docker compose up -d
docker compose logs web     # shows the credentials generated on first boot
```

On first boot, if you don't set `ADMIN_PASSWORD`, a **secure random password** is
generated and printed to the console **once**. The `SECRET_KEY` is also generated and
persisted to `data/secret_key`. To pin your own, set `ADMIN_USERNAME` /
`ADMIN_PASSWORD` / `SECRET_KEY` in `.env`.

Open `http://<host>:8000`.

> **Run it behind TLS.** Session cookies are issued over the configured transport.
> Put TrueVector behind a reverse proxy with HTTPS and set `HTTPS_ONLY=true`.
> See [SECURITY.md](SECURITY.md) for the full deployment checklist.

### Local development

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## Workflow

1. **Configure** (`/settings`): outbound SMTP + target mailbox and reader backend
   (IMAP or Microsoft Graph). Use **Test connection** to validate both before sending.
2. **Review techniques** (`/tasks`): preview the exact content of each technique.
3. **Create and launch a campaign** (`/campaigns/new`): pick techniques and launch.
4. **Automatic 5-layer analysis**: delivery, gateway verdict, body transformations,
   attachments and images.
5. **Score & risk**: protection % + MITRE ATT&CK attack chains.
6. **PDF report** (`/campaigns/{id}/report.pdf`): executive summary + remediation plan.

### Delivery states and scoring

| State | Weight | Meaning |
|---|---|---|
| `INBOX` | 0.0 | Reached the inbox — **gateway failure** |
| `JUNK` | 0.5 | Sent to junk/spam — partial |
| `MISSING` | 1.0 | Absent after the retry window — **blocked/quarantined** |
| `NOT_FOUND` | — | Inconclusive (late delivery, read failure…). **Excluded from the score** so it never inflates protection. |

### Delivery-wait strategy (two-phase polling)

The reader doesn't use a fixed window: it **waits for the first message** to land in
any folder (up to `READ_FIRST_TIMEOUT`), then keeps polling and **marking each arrival
live** (the page auto-refreshes) until a quiet period passes with no new message
(`READ_QUIET_PERIOD`) or the absolute cap is hit. This tolerates gateways that delay
delivery for detonation/sandboxing.

| Variable | Default | Meaning |
|---|---|---|
| `READ_FIRST_TIMEOUT` | 600s | Max wait for the **first** message |
| `READ_QUIET_PERIOD` | 180s | Idle window after the **last** arrival before closing |
| `READ_POLL_INTERVAL` | 15s | Interval between polls |
| `READ_ABSOLUTE_TIMEOUT` | 1800s | Hard cap for the whole wait |

The worker runs in a **background thread**, so the wait never blocks the app.

---

## Technique catalog

| ID | Technique | Category |
|----|-----------|----------|
| T01 | Base64-encoded HTML body | Content evasion |
| T02 | ZIP attachment with HTML | Attachment delivery |
| T03 | HTML attachment (local phishing) | Attachment delivery |
| T04 | SVG attachment with script | Script execution |
| T05 | Office macro document (.docm) | Office macro |
| T06 | Zero-width spaces in URLs | URL obfuscation |
| T07 | baseStriker (`<base>` tag) | URL obfuscation |
| T08 | Calendar invite (.ics) | Calendar delivery |
| T09 | EICAR as attachment | AV evasion |
| T10 | Link to EICAR (URL reputation) | URL reputation |
| T11 | External image (hotlink) | External beaconing |
| T12 | Display-name spoofing | Identity spoofing |
| T13 | Unicode homoglyph URL | URL obfuscation |
| T14 | Plain-text URL (no href) | URL analysis evasion |
| T15 | Polyglot HTML/JS payload | Script execution |
| T16 | HTML smuggling (Blob API attachment) | HTML smuggling |
| T17 | HTML smuggling (external link) | HTML smuggling |
| T18 | Password-protected ZIP | Encrypted delivery |
| T19 | ISO disk image (.iso) | Disk image |
| T20 | OneNote attachment (.one) | Office alternative |
| T21 | PDF with JavaScript (OpenAction) | Malicious PDF |
| T22 | Open redirect via trusted domain | Open redirect |
| T23 | Reply-To mismatch (BEC) | BEC / Fraud |
| T24 | MIME type mismatch (HTML as image) | MIME evasion |
| T25 | LNK shortcut in ZIP | LNK dropper |
| T26 | URL as HTML entities | URL obfuscation |
| T27 | Dynamic URL via data-attributes | Dynamic URL obfuscation |
| T28 | QR code phishing | QR phishing |
| T29 | Payload on trusted cloud storage (Azure Blob / S3) | Trusted-host delivery |

> **T17, T28 and T29 deliver their payload through infrastructure you host.** They
> require the matching field in **Settings → Payload hosting** (a web server base URL
> and/or a trusted-cloud payload URL). Until configured, they are disabled in the
> campaign picker and skipped on launch, so they never send a broken placeholder.

---

## Methodology (important for reliable results)

- **Send from an external, untrusted domain.** If sender and recipient are in the same
  tenant (e.g. the same Microsoft 365), "internal" mail is often scanned differently
  from a real external attack, and your provider's **outbound** filter may strip the
  payload before it reaches the inbound gateway you want to audit. To represent a real
  attacker, the origin must be external.
- **Clean the carrier, not the payload.** Junk placement can come from *sender
  reputation/authentication* (noise) or from *content detection* (the signal you want).
  Use a properly authenticated sending domain (SPF/DKIM/DMARC) so junk reflects the
  gateway's verdict on the payload — don't weaken the techniques. The correlation token
  lives only in the `X-Validator-ID` header, so the subject stays natural.
- **Pace the run and let it order itself.** A new sender that bursts ~29 odd messages at one
  mailbox is a suspicious pattern in itself — the gateway can degrade the sender's reputation
  *mid-run*, so late emails get a worse verdict for reasons unrelated to their payload. TrueVector
  spaces the sends (`Settings → Sending pace`, default 90 ± 30s, with jitter so it doesn't look like
  a cron) and sends **stealthiest techniques first, loud basic-detection ones (EICAR, macros) last**,
  so a late reputation hit never contaminates the subtle vectors. Set the interval to `0` for a fast
  lab burst. A full run takes ~30–60 min at the default pace.
- **Trust the canaries, not your assumptions.** With a single sender you can't fully *prevent*
  reputation contamination, so TrueVector *measures* it: it interleaves benign **control canaries**
  (payload-free emails) through the run. If they keep landing in the inbox, the carrier held and every
  verdict is trustworthy; if they start going to Junk/blocked partway through, the report flags every
  technique sent afterwards as **carrier-suspect** — so a late "block" is never mistaken for real
  detection when it's actually a burned sender. Toggle in `Settings → Sending pace`.
- **Mind your sending account.** Emitting EICAR/macros/ISO/LNK from a real authenticated
  account can get it flagged or suspended. Use a dedicated test account.
- **Detonation/sandbox = delays.** Gateways with Safe Attachments/ATP can delay delivery
  for minutes. If a message exceeds the retry window it's marked `NOT_FOUND`
  (inconclusive), not blocked. Re-run or check the mailbox if you expect slow detonation.

---

## Validation

Self-check with no external services (temporary DB; exercises the worker, scoring,
T12 spoofing, the reader's two-phase polling, orphan sweep and PDF generation):

```bash
python scripts/selfcheck.py
```

For real over-the-wire send/read there are two paths:

- **Local test mail server (GreenMail, no Docker).** Needs Java 17+. Validates the full
  real pipeline (SMTP send → delivery → IMAP read → classification → attachments),
  although it delivers everything to the inbox (no gateway → 0% score):
  ```bash
  pwsh scripts/run_greenmail.ps1 start
  python scripts/greenmail_test.py
  pwsh scripts/run_greenmail.ps1 stop
  ```
- **A real test mailbox** (Gmail/Outlook with an app password, or M365 via Graph) behind
  the gateway you want to audit — the only way to validate **real classification**
  (Inbox/Junk/blocked, Safe Links, banners, etc.).

---

## Known limitations

- An interrupted campaign (process restart mid-run) is marked `error` on next boot.
- The Google Workspace (Gmail API) reader backend is stubbed; use IMAP or Microsoft
  Graph.

## License

[MIT](LICENSE).
