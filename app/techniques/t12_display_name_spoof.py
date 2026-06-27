from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_HTML = """<html><body>
<p>Dear Customer,</p>
<p>We detected unusual activity on your account. Please verify immediately:</p>
<p><a href="http://probe.test.invalid/t12">Verify my account</a></p>
<p>— PayPal Security Team</p>
</body></html>"""


class T12DisplayNameSpoof(Technique):
    meta = TechniqueMeta(
        id="T12",
        name="Display name spoofing",
        threat="Identity spoofing — the sender's display name imitates a trusted brand even though the real domain differs. Tests whether the gateway warns the user.",
        # sender.py spoofs the visible From display name with this value
        spoof_from_name="PayPal Security Team",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        # The From display name is spoofed to "PayPal Security Team" via meta.spoof_from_name
        msg["Subject"] = "PayPal: Unusual activity detected on your account"
        msg["Reply-To"] = "security-noreply@probe.test.invalid"
        msg.attach(MIMEText("Unusual activity detected. See HTML version.", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
