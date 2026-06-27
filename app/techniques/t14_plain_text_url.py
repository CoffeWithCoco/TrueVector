from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_BODY = """Your password will expire in 24 hours.

Reset it now: http://probe.test.invalid/t14/reset?token=abc123xyz

If you did not request this, ignore this message.

-- IT Security Team
"""


class T14PlainTextUrl(Technique):
    meta = TechniqueMeta(
        id="T14",
        name="Plain-text URL (no href)",
        threat="Format-based evasion — a plain-text URL with no <a> tag; some gateways only analyze href attributes and ignore literal URLs in plain text.",
    )

    def build_message(self) -> Message:
        msg = MIMEText(_BODY, "plain", "utf-8")
        msg["Subject"] = "Action required: password expiry in 24h"
        return msg
