from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_HTML = """<html><body>
<p>Your account statement is ready:</p>
<img src="http://probe.test.invalid/t11/pixel.png" width="1" height="1" alt="">
<img src="http://probe.test.invalid/t11/banner.png" width="600" height="200" alt="Account Statement">
<p><a href="http://probe.test.invalid/t11">View full statement</a></p>
</body></html>"""


class T11ExternalImage(Technique):
    meta = TechniqueMeta(
        id="T11",
        name="External image (hotlink)",
        threat="Exfiltration and tracking — images loaded from an external server; the gateway should block or proxy the URLs to prevent beaconing.",
        expected_images=True,
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your account statement — June 2026"
        msg.attach(MIMEText("Your account statement is ready. Enable HTML to view.", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
