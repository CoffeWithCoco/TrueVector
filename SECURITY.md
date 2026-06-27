# Security Policy

## Authorized use

TrueVector emits the EICAR test file, macro-enabled documents, disk-image and
shortcut attachments, and phishing-style payloads in order to measure how an email
gateway handles them. **Only run it against mailboxes and tenants you own or are
explicitly authorized to test.** Using it against third parties without consent may
be illegal and is not a supported use case. The payloads are inert, but the authors
accept no liability for misuse.

## Deployment checklist

TrueVector stores live secrets (SMTP credentials, Microsoft Graph client secret, the
session signing key) and is intended to run on infrastructure controlled by the
deployer. Before exposing it beyond `localhost`:

- [ ] **Serve over TLS.** Put it behind a reverse proxy (nginx, Caddy, Traefik) with
      HTTPS and set `HTTPS_ONLY=true` so session cookies are marked secure.
- [ ] **Set a strong admin password.** Either let the first boot generate one (printed
      once to the console) or set `ADMIN_PASSWORD` to a strong value. Never ship the
      default `admin`.
- [ ] **Set a persistent `SECRET_KEY`** in the environment for multi-instance deploys,
      or rely on the auto-generated `data/secret_key`.
- [ ] **Protect `data/`.** The SQLite database holds credentials in plaintext. Keep the
      file private, back it up encrypted, and never commit it (it is git-ignored).
- [ ] **Restrict network access** to the admin UI (VPN, IP allowlist, or an
      authenticating proxy) — there is no multi-user RBAC.
- [ ] **Use a dedicated sending account**, not a production mailbox.

Secrets and local data (`.env`, `data/*.db`, `data/secret_key`) are excluded from both
git (`.gitignore`) and the Docker image (`.dockerignore`).

## Known security notes

- Secrets are stored unencrypted in the local SQLite DB. This is acceptable for the
  intended single-operator, locally-controlled deployment (anyone who can read the DB
  can also read the key), but plan accordingly if you deploy on shared infrastructure.
- There is no CSRF token; state-changing requests rely on `SameSite=Lax` session
  cookies. Do not relax the cookie policy without adding CSRF protection.
- `/login` is not rate-limited; add throttling at the proxy if exposed.

## Reporting a vulnerability

Please open a private report (GitHub Security Advisory) or contact the maintainer
rather than filing a public issue with exploit details. Include reproduction steps and
the affected version/commit.
