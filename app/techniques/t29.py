"""T29 — EICAR hosted on trusted cloud storage (Azure Blob / S3) [NEEDS-CLOUD]."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta, RuntimeContext

_PLACEHOLDER = "https://<your-account>.blob.core.windows.net/<container>/eicar.com"


class T29(Technique):
    meta = TechniqueMeta(
        id="T29",
        name="Payload on trusted cloud storage (Azure Blob / S3)",
        threat="Link to an AV-detectable payload (EICAR) hosted on Azure Blob / AWS S3. "
               "Because the URL lives on a Microsoft/Amazon domain that proxies, VPN "
               "allowlists and URL-category filters treat as trusted, reputation-based "
               "controls are often bypassed - 'living off trusted sites'.",
        needs_web=True,
        requires="cloud_payload_url",
    )

    def _build(self, url: str, configured: bool) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Document ready for download"
        msg.set_content(f"Your document is available here: {url}")
        note = "" if configured else (
            "<p style='color:#888;font-size:12px;'>[NEEDS-CLOUD] Upload EICAR to your Azure Blob "
            "/ S3 bucket and set its URL in Settings -> Payload hosting.</p>"
        )
        msg.add_alternative(
            f"<html><body>"
            f"<p>Your requested document is ready.</p>"
            f"<p><a href='{url}'>Download from secure storage</a></p>"
            f"{note}"
            f"</body></html>",
            subtype="html",
        )
        return msg

    def build_message(self) -> Message:
        return self._build(_PLACEHOLDER, configured=False)

    def render(self, ctx: RuntimeContext | None = None) -> Message:
        url = (ctx.cloud_payload_url if ctx else "").strip()
        if not url:
            return self._build(_PLACEHOLDER, configured=False)
        return self._build(url, configured=True)
