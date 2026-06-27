from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

_ICS = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//MailProbe//T08//EN
BEGIN:VEVENT
DTSTART:20260615T100000Z
DTEND:20260615T110000Z
SUMMARY:Urgent: Account Verification Required
DESCRIPTION:Please verify your account at http://probe.test.invalid/t08
URL:http://probe.test.invalid/t08
ORGANIZER;CN=Security Team:mailto:security@probe.test.invalid
END:VEVENT
END:VCALENDAR"""


class T08IcsCalendar(Technique):
    meta = TechniqueMeta(
        id="T08",
        name="Calendar invite (.ics)",
        threat="Calendar-phishing vector — .ics invites are auto-added to the calendar and carry URLs that bypass many gateways.",
        expected_attachments=["invite.ics"],
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart()
        msg["Subject"] = "Meeting invitation: Account verification"
        msg.attach(MIMEText("You have received a meeting invitation.", "plain", "utf-8"))

        att = MIMEApplication(_ICS.encode(), _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename="invite.ics")
        att.add_header("Content-Type", "text/calendar; method=REQUEST")
        msg.attach(att)
        return msg
