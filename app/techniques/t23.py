"""T23 — Reply-To mismatch (Business Email Compromise)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


class T23(Technique):
    meta = TechniqueMeta(
        id="T23",
        name="Reply-To mismatch (BEC)",
        threat="From shows an apparently legitimate domain but Reply-To points to an attacker domain. "
               "Core Business Email Compromise technique — the gateway should detect the mismatch.",
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Urgent: Wire Transfer Request — CEO"
        msg["Reply-To"] = "urgent-cfo@secure-finance-dept.com"
        msg.set_content(
            "This is an urgent request.\n\n"
            "Please process a wire transfer of $48,500 to our new vendor account.\n"
            "I'm in a meeting and cannot be reached by phone — reply to this email to confirm.\n\n"
            "Thank you,\nCEO"
        )
        msg.add_alternative(
            "<html><body>"
            "<p>This is an urgent request.</p>"
            "<p>Please process a wire transfer of <strong>$48,500</strong> to our new vendor account.</p>"
            "<p>I'm in a meeting and cannot be reached by phone — <strong>reply to this email</strong> to confirm.</p>"
            "<br><p>Thank you,<br>CEO</p>"
            "</body></html>",
            subtype="html",
        )
        return msg
