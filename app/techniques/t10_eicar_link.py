from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_HTML = """<html><body>
<p>Please download and run the security validation tool:</p>
<p><a href="https://www.eicar.org/download/eicar.com">Download security tool</a></p>
<p>Direct link: https://www.eicar.org/download/eicar.com.txt</p>
</body></html>"""


class T10EicarLink(Technique):
    meta = TechniqueMeta(
        id="T10",
        name="Link to EICAR (URL reputation)",
        threat="URL reputation — link to eicar.org; the gateway should detect that the URL leads to AV-detectable content and block it.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Download required — security tool"
        msg.attach(MIMEText("Download from https://www.eicar.org/download/eicar.com", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
