import smtplib
import ssl
import uuid
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..models import Config


def test_smtp(config: Config) -> tuple[bool, str]:
    """Connect to the configured SMTP server and authenticate, without sending."""
    if not config or not config.smtp_host:
        return False, "SMTP host is required."
    try:
        context = ssl.create_default_context()
        port = int(config.smtp_port or 587)
        if port == 465:
            with smtplib.SMTP_SSL(config.smtp_host, port, context=context, timeout=20) as smtp:
                if config.smtp_user and config.smtp_pass:
                    smtp.login(config.smtp_user, config.smtp_pass)
        else:
            with smtplib.SMTP(config.smtp_host, port, timeout=20) as smtp:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    smtp.starttls(context=context)
                    smtp.ehlo()
                if config.smtp_user and config.smtp_pass:
                    smtp.login(config.smtp_user, config.smtp_pass)
        return True, f"Connected and authenticated to {config.smtp_host}:{port}."
    except Exception as exc:
        return False, f"SMTP error: {exc}"


def build_validator_id(campaign_id: int, technique_id: str) -> str:
    """Unique ID carried in the X-Validator-ID header. Used by the reader to locate the message."""
    return f"{campaign_id}-{technique_id}-{uuid.uuid4().hex[:8]}"


def _smtp_send(config: Config, msg: EmailMessage) -> None:
    """Open a connection to the configured SMTP server and send one message."""
    context = ssl.create_default_context()
    port = int(config.smtp_port or 587)
    if port == 465:
        # Implicit TLS (SMTPS)
        with smtplib.SMTP_SSL(config.smtp_host, port, context=context) as smtp:
            if config.smtp_user and config.smtp_pass:
                smtp.login(config.smtp_user, config.smtp_pass)
            smtp.send_message(msg)
    else:
        # Plain connection, upgrade with STARTTLS only if the server offers it
        with smtplib.SMTP(config.smtp_host, port) as smtp:
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls(context=context)
                smtp.ehlo()
            if config.smtp_user and config.smtp_pass:
                smtp.login(config.smtp_user, config.smtp_pass)
            smtp.send_message(msg)


# Benign, payload-free emails used as carrier-reputation canaries. Plain text,
# natural subjects, no links/attachments — so where they land reflects the
# sender's standing, not any content detection. Rotated so they don't look like
# one identical bulk message repeated.
_CANARY_TEMPLATES = [
    ("Notes from today's sync",
     "Hi,\n\nThanks for the time earlier. Quick recap of what we agreed:\n"
     "- I'll share the updated timeline by Friday.\n"
     "- You'll loop in the rest of the team.\n\n"
     "Shout if I missed anything.\n\nBest,\nDana"),
    ("Re: lunch next week",
     "Sounds good - Tuesday works for me. Let's say 12:30 at the usual place.\n\n"
     "See you then,\nAlex"),
    ("Monthly update is ready",
     "Hello,\n\nThis month's update covers the new office hours and a couple of small "
     "process changes. Nothing urgent - have a read when you get a moment.\n\nThanks,\nThe team"),
    ("Quick question about the report",
     "Hey,\n\nDo you have the latest figures for the quarterly summary? No rush, just "
     "want to make sure I'm using the right numbers.\n\nCheers,\nJordan"),
    ("Reminder: team photo Thursday",
     "Hi all,\n\nFriendly reminder that the team photo is on Thursday at 10am in the lobby.\n\n"
     "Thanks,\nFacilities"),
    ("Following up",
     "Hi,\n\nJust following up on my note from last week - let me know if you need anything "
     "else from my side to move forward.\n\nBest regards,\nSam"),
]


def send_canary(config: Config, campaign_id: int, target_email: str, index: int) -> str:
    """Send one benign control canary. Returns its validator_id."""
    validator_id = build_validator_id(campaign_id, f"CANARY{index:02d}")
    subject, body = _CANARY_TEMPLATES[index % len(_CANARY_TEMPLATES)]

    msg = EmailMessage()
    msg.set_content(body)
    from_email = config.smtp_user or f"probe@{config.from_domain}"
    msg["From"] = f"{config.from_name or 'Security Validator'} <{from_email}>"
    msg["To"] = target_email
    msg["Subject"] = subject
    msg["X-Validator-ID"] = validator_id
    msg["X-Mailer"] = "MailProbe/1.0"
    if not msg["Date"]:
        msg["Date"] = formatdate(localtime=True)
    if not msg["Message-ID"]:
        domain = (config.from_domain or "mailprobe.local").split("@")[-1]
        msg["Message-ID"] = make_msgid(domain=domain)

    _smtp_send(config, msg)
    return validator_id


def send_technique(
    config: Config,
    technique,
    campaign_id: int,
    target_email: str,
    ctx=None,
) -> str:
    """
    Build and send one technique email.
    Returns the validator_id used so it can be stored in Result.
    `ctx` is a RuntimeContext injecting deploy-specific URLs for hosted-payload
    techniques; self-contained techniques ignore it.
    """
    validator_id = build_validator_id(campaign_id, technique.meta.id)

    msg: EmailMessage = technique.render(ctx)

    # Use smtp_user as the actual sender address — hosted providers (Outlook, Gmail)
    # reject From addresses that don't match the authenticated account.
    # from_domain is kept for SPF/DKIM labeling in reports only.
    from_email = config.smtp_user or f"probe@{config.from_domain}"
    # A technique may spoof the visible display name (e.g. "PayPal Security Team")
    # while the real address stays the authenticated account — the classic
    # display-name spoof that the gateway is supposed to flag.
    display_name = technique.meta.spoof_from_name or config.from_name
    msg["From"] = f"{display_name} <{from_email}>"
    msg["To"] = target_email
    # Correlation token lives ONLY in this header — never in the subject. A weird
    # token in the subject is itself a spam heuristic, and since the reader has
    # full mailbox access it can locate the message by header (IMAP SEARCH HEADER
    # / Graph internetMessageHeaders). This keeps the subject natural so junk
    # placement reflects the gateway's verdict on the payload, not the envelope.
    msg["X-Validator-ID"] = validator_id
    msg["X-Mailer"] = "MailProbe/1.0"

    # Ensure well-formed headers even if the MTA doesn't add them (e.g. test servers)
    if not msg["Date"]:
        msg["Date"] = formatdate(localtime=True)
    if not msg["Message-ID"]:
        domain = (config.from_domain or "mailprobe.local").split("@")[-1]
        msg["Message-ID"] = make_msgid(domain=domain)

    # Subject is left exactly as the technique authored it.
    if not msg.get("Subject"):
        msg["Subject"] = technique.meta.name

    _smtp_send(config, msg)
    return validator_id
