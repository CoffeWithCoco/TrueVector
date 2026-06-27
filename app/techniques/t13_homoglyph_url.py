from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# Homoglyph: Cyrillic 'а' (U+0430) instead of Latin 'a'
# pаypal.com looks identical to paypal.com in many fonts
_FAKE_DOMAIN = "pаypаl.com"  # Cyrillic а
_HTML = f"""<html><body>
<p>Your PayPal account requires verification.</p>
<p>Visit: <a href="http://probe.test.invalid/t13">{_FAKE_DOMAIN}</a></p>
<p>Or copy this link: http://{_FAKE_DOMAIN}/verify</p>
</body></html>"""


class T13HomoglyphUrl(Technique):
    meta = TechniqueMeta(
        id="T13",
        name="Unicode homoglyph URL",
        threat="Visual domain confusion — Unicode characters visually identical to Latin letters (Cyrillic, Greek) in the URL deceive the user and evade reputation analysis.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "PayPal: Your account needs attention"
        msg.attach(MIMEText(f"Visit {_FAKE_DOMAIN} to verify your account.", "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
