from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# Polyglot: valid as both HTML and JavaScript.
# The outer layer looks like a plain text/plain MIME part but contains a
# secondary HTML comment that includes an active link — tests parsers that
# only inspect the first MIME part.
_PLAIN = "Please read the security notice below.\n\n<!--\n<a href='http://probe.test.invalid/t15'>Click here</a>\n-->"
_HTML = """<html><body>
<p>MailProbe T15 — Polyglot HTML/JS test.</p>
<!-- js payload hidden from some scanners:
<script>window.location='http://probe.test.invalid/t15'</script>
-->
<noscript><a href="http://probe.test.invalid/t15">Proceed</a></noscript>
</body></html>"""


class T15PolyglotHtmlJs(Technique):
    meta = TechniqueMeta(
        id="T15",
        name="Polyglot HTML/JS payload",
        threat="Format-ambiguity evasion — content valid as multiple MIME types; scripts hidden in HTML comments that some gateway parsers do not inspect.",
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Security notice — please read"
        msg.attach(MIMEText(_PLAIN, "plain", "utf-8"))
        msg.attach(MIMEText(_HTML, "html", "utf-8"))
        return msg
