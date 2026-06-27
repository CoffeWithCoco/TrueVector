"""T26 — URL encoded as HTML entities."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta

_RAW_URL = "https://eicar.org"
_ENCODED  = "".join(f"&#x{ord(c):02x};" for c in _RAW_URL)


class T26(Technique):
    meta = TechniqueMeta(
        id="T26",
        name="URL as HTML entities",
        threat="URL encoded as HTML entities (&#x68;&#x74;&#x74;&#x70;...). "
               "URL parsers that don't decode entities before analysis detect no link at all.",
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Security Alert — Immediate Action Required"
        msg.set_content(f"Review this security notice: {_RAW_URL}")
        msg.add_alternative(
            f"<html><body>"
            f"<p>Click <a href=\"{_ENCODED}\">here</a> to review the security alert.</p>"
            f"</body></html>",
            subtype="html",
        )
        return msg
