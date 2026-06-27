from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# Zero-width space U+200B inserted inside URL and domain names to break regex matching
_ZWS = "​"
_HTML = f"""<html><body>
<p>Your account requires immediate attention.</p>
<p>Visit: <a href="http://probe.test.invalid/t06">
  http://probe.{_ZWS}test{_ZWS}.invalid/t06
</a></p>
<p>Reference: pay{_ZWS}pal.com security notice</p>
</body></html>"""


class T06ZeroWidthSpaces(Technique):
    meta = TechniqueMeta(
        id="T06",
        name="Zero-width spaces in URLs",
        threat="Lexical-analysis evasion — zero-width characters (U+200B) break the gateway's regex while the mail client still renders the URL correctly.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Security notice — action required"
        msg.attach(MIMEText("Action required. See HTML version.", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
