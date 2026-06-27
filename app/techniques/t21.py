"""T21 — PDF with JavaScript action (OpenAction)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


def _build_pdf(js: str) -> bytes:
    """Minimal valid PDF-1.4 with an OpenAction JavaScript."""
    objs = {
        1: f"<</Type /Catalog /Pages 2 0 R /OpenAction 4 0 R>>",
        2: f"<</Type /Pages /Kids [3 0 R] /Count 1>>",
        3: f"<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>",
        4: f"<</Type /Action /S /JavaScript /JS ({js})>>",
    }
    buf = b"%PDF-1.4\n"
    offsets: dict[int, int] = {}
    for num, body in objs.items():
        offsets[num] = len(buf)
        buf += f"{num} 0 obj {body} endobj\n".encode()

    xref_off = len(buf)
    buf += b"xref\n"
    buf += f"0 {len(objs)+1}\n".encode()
    buf += b"0000000000 65535 f \n"
    for n in range(1, len(objs)+1):
        buf += f"{offsets[n]:010d} 00000 n \n".encode()
    buf += f"trailer <</Size {len(objs)+1} /Root 1 0 R>>\n".encode()
    buf += f"startxref\n{xref_off}\n%%EOF\n".encode()
    return buf


class T21(Technique):
    meta = TechniqueMeta(
        id="T21",
        name="PDF with JavaScript (OpenAction)",
        threat="PDF with a JavaScript action that runs on open with no user interaction. "
               "The gateway must detect and block JS embedded in PDFs.",
        expected_attachments=["contract.pdf"],
    )

    def build_message(self) -> Message:
        pdf = _build_pdf(r"app.alert('MailProbe T21 - PDF JavaScript detected');")
        msg = EmailMessage()
        msg["Subject"] = "Contract Document — Signature Required"
        msg.set_content("Please review and sign the attached contract.")
        msg.add_attachment(
            pdf,
            maintype="application",
            subtype="pdf",
            filename="contract.pdf",
        )
        return msg
