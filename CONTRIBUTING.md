# Contributing

Thanks for your interest in improving TrueVector.

## Getting started

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (use: source .venv/bin/activate on Unix)
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Run the self-check before sending a PR — it exercises the worker, scoring, the reader's
two-phase polling and PDF generation with no external services:

```bash
python scripts/selfcheck.py
```

## Adding a new evasion technique

Each technique is a self-contained module under `app/techniques/` and is auto-discovered
at startup. To add one:

1. Create `app/techniques/tNN_short_name.py`.
2. Subclass `Technique` and define a `meta = TechniqueMeta(...)` with a unique `id`
   (e.g. `"T29"`), a short English `name`, and a one-line `threat` description.
   Declare `expected_attachments` / `expected_images` if the analyzer should check for
   them. The attachment names in `expected_attachments` **must match the filenames you
   actually attach** in `build_message()`.
3. Implement `build_message()` returning a `Message`. Do **not** set `From`, `To`,
   `Subject` ownership of correlation, or `X-Validator-ID` — `sender.py` handles those.
   Keep the subject natural; the correlation token travels only in the
   `X-Validator-ID` header.
4. (Optional) Add a risk profile in `app/core/risk.py` (`PROFILES`) and wire it into any
   relevant attack chain (`CHAINS`).
5. Keep payloads **inert** — no real malware. Use markers like `MAILPROBE-TNN-…`.

## Style

- English for all user-facing strings, identifiers and comments.
- Match the surrounding code's conventions; standard library over new dependencies
  where practical (the Microsoft Graph backend is stdlib-only by design).

## Pull requests

- Keep changes focused and describe the testing you did.
- Run `scripts/selfcheck.py` and confirm it passes (15/15).
