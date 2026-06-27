"""T24 — MIME type mismatch (HTML attachment declared as image/gif)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta

_HTML = (
    "<!DOCTYPE html><html><body>"
    "<h1>MAILPROBE T24 - MIME Type Mismatch</h1>"
    "<p>This file is HTML but was declared as image/gif.</p>"
    "<script>document.title='MAILPROBE-T24';</script>"
    "</body></html>"
).encode("ascii")


class T24(Technique):
    meta = TechniqueMeta(
        id="T24",
        name="MIME type mismatch (HTML as image)",
        threat="HTML file sent with Content-Type: image/gif. "
               "Gateways that trust the declared MIME type without verifying the content's real magic bytes won't analyze the HTML or its JavaScript.",
        expected_attachments=["banner.gif"],
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Product Images — Q4 Marketing Campaign"
        msg.set_content("Please find the product images for the Q4 campaign attached.")
        msg.add_attachment(
            _HTML,
            maintype="image",
            subtype="gif",
            filename="banner.gif",
        )
        return msg
