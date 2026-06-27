from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# baseStriker: <base href="..."> sets the base URL.
# href="/t07" alone looks harmless; the browser resolves to "http://probe.test.invalid/t07"
_HTML = """<html>
<head>
  <base href="http://probe.test.invalid">
</head>
<body>
  <p>Please review and sign the attached document.</p>
  <a href="/t07">Sign document</a>
</body>
</html>"""


class T07BaseStriker(Technique):
    meta = TechniqueMeta(
        id="T07",
        name="baseStriker (<base> tag)",
        threat="Link-analysis evasion — the <base> tag splits the malicious URL; the gateway analyzes '/t07' (harmless) while the client resolves the full URL.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Document signature required"
        msg.attach(MIMEText("Please open the HTML version to sign the document.", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
