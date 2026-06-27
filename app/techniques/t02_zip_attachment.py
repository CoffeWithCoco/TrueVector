import io
import zipfile
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_INNER_HTML = """<html><body>
<h2>Invoice #2026-001</h2>
<p><a href="http://probe.test.invalid/t02">Download full invoice</a></p>
</body></html>"""


class T02ZipAttachment(Technique):
    meta = TechniqueMeta(
        id="T02",
        name="ZIP attachment with HTML",
        threat="Compressed-payload delivery — malicious HTML file inside a ZIP to evade attachment inspection.",
        expected_attachments=["invoice.zip"],
    )

    def build_message(self) -> Message:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("invoice.html", _INNER_HTML)
        zip_data = buf.getvalue()

        msg = MIMEMultipart()
        msg["Subject"] = "Attached invoice — Q2 2026"
        msg.attach(MIMEText("The invoice is attached in compressed format.", "plain", "utf-8"))

        att = MIMEApplication(zip_data, _subtype="zip")
        att.add_header("Content-Disposition", "attachment", filename="invoice.zip")
        msg.attach(att)
        return msg
