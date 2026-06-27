"""T17 — HTML smuggling via external link [NEEDS-WEB]."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta, RuntimeContext

_PLACEHOLDER = "http://NEEDS-WEB-SERVER/smuggle"


class T17(Technique):
    meta = TechniqueMeta(
        id="T17",
        name="HTML smuggling (external link)",
        threat="Link to a controlled page that builds and delivers the payload via the Blob API. "
               "The gateway only sees a URL; the file is generated entirely in the target's browser.",
        needs_web=True,
        requires="web_base_url",
    )

    def _build(self, url: str, configured: bool) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Shared Document — Review Required"
        msg.set_content(f"Please review the document: {url}")
        note = "" if configured else (
            "<p style='color:#888;font-size:12px;'>[NEEDS-WEB] Set the web server base URL "
            "in Settings -> Payload hosting to deliver the smuggling page.</p>"
        )
        msg.add_alternative(
            f"<html><body>"
            f"<p>Please <a href='{url}'>click here</a> to review the shared document.</p>"
            f"{note}"
            f"</body></html>",
            subtype="html",
        )
        return msg

    def build_message(self) -> Message:
        return self._build(_PLACEHOLDER, configured=False)

    def render(self, ctx: RuntimeContext | None = None) -> Message:
        base = (ctx.web_base_url if ctx else "").rstrip("/")
        if not base:
            return self._build(_PLACEHOLDER, configured=False)
        return self._build(f"{base}/smuggle", configured=True)
