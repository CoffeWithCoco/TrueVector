import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_HTML = """<html><body>
<p>This is a security validation test from MailProbe.</p>
<p><a href="http://probe.test.invalid/t01">Click here to verify your account</a></p>
</body></html>"""


class T01Base64Body(Technique):
    meta = TechniqueMeta(
        id="T01",
        name="Base64-encoded HTML body",
        threat="Content-inspection evasion — HTML body encoded in base64 to bypass the gateway's lexical analysis.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Account verification required"

        plain = MIMEText("Click the link to verify your account.", "plain", "utf-8")

        # Force base64 encoding explicitly — the evasion technique
        html_part = MIMEText("", "html", "utf-8")
        html_part.set_payload(base64.b64encode(_HTML.encode()).decode())
        html_part.replace_header("Content-Transfer-Encoding", "base64")

        msg.attach(plain)
        msg.attach(html_part)
        return msg
