from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <script type="text/javascript">
    // MailProbe T04 — SVG with inline script (inert)
    var url = "http://probe.test.invalid/t04";
  </script>
  <text x="10" y="50" font-size="14">Click to view document</text>
  <a href="http://probe.test.invalid/t04">
    <rect x="10" y="60" width="150" height="40" fill="#6366f1"/>
  </a>
</svg>"""


class T04SvgAttachment(Technique):
    meta = TechniqueMeta(
        id="T04",
        name="SVG attachment with script",
        threat="XSS via vector image — the SVG runs JavaScript in the browser when opened, evading attachment filters.",
        expected_attachments=["document.svg"],
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart()
        msg["Subject"] = "Shared document — please review the attachment"
        msg.attach(MIMEText("A document has been shared with you.", "plain", "utf-8"))

        att = MIMEApplication(_SVG.encode(), _subtype="svg+xml")
        att.add_header("Content-Disposition", "attachment", filename="document.svg")
        msg.attach(att)
        return msg
