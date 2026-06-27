"""T28 — QR code phishing [NEEDS-WEB / NEEDS-IMAGE]."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta, RuntimeContext


class T28(Technique):
    meta = TechniqueMeta(
        id="T28",
        name="QR code phishing",
        threat="The malicious URL is encoded into a QR image embedded in the email body. "
               "Gateways don't OCR images, so no URL-reputation engine detects it.",
        expected_images=True,
        needs_web=True,
        requires="web_base_url",
    )

    def _build(self, target: str, configured: bool) -> Message:
        note = (
            f"Generate a QR for <code>{target}</code> and embed it as an inline image "
            f"(<code>cid:qr@mailprobe</code>)."
            if configured else
            "[NEEDS-WEB] Set the web server base URL in Settings -> Payload hosting, then embed a "
            "QR image that encodes it (<code>cid:qr@mailprobe</code>)."
        )
        html = (
            "<html><body>"
            "<p>Please scan the QR code below to complete your account verification:</p>"
            "<p style='text-align:center;padding:20px;background:#f5f5f5;border-radius:8px;'>"
            "<strong>[NEEDS-IMAGE]</strong><br><br>"
            f"{note}<br><br>"
            "Requires the <code>qrcode</code> library or a pre-generated image."
            "</p>"
            "</body></html>"
        )
        msg = EmailMessage()
        msg["Subject"] = "Account Verification Required — Scan QR Code"
        msg.set_content(
            f"[NEEDS-IMAGE] This template requires a QR code image encoding {target}."
        )
        msg.add_alternative(html, subtype="html")
        return msg

    def build_message(self) -> Message:
        return self._build("https://your-landing.example/verify", configured=False)

    def render(self, ctx: RuntimeContext | None = None) -> Message:
        base = (ctx.web_base_url if ctx else "").rstrip("/")
        if not base:
            return self._build("https://your-landing.example/verify", configured=False)
        return self._build(f"{base}/verify", configured=True)
