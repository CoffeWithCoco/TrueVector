from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# Standard EICAR test string — harmless, but every AV must detect it
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class T09EicarAttachment(Technique):
    meta = TechniqueMeta(
        id="T09",
        name="EICAR as attachment",
        threat="Gateway AV validation — the EICAR test is the standard way to verify that the gateway's antivirus engine is active and working.",
        expected_attachments=["eicar.com"],
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart()
        msg["Subject"] = "Test file attached"
        msg.attach(MIMEText("Please scan the attached file.", "plain", "utf-8"))

        att = MIMEApplication(EICAR, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="eicar.com")
        msg.attach(att)
        return msg
