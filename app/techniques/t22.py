"""T22 — Open redirect via high-trust domain."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta

# Google's open redirect — gateway sees google.com (high reputation),
# not the actual destination. Tests if gateway follows redirect chains.
_URL = "https://www.google.com/url?q=https://eicar.org&sa=D&source=mail&usg=AOvVaw1mailprobetest"


class T22(Technique):
    meta = TechniqueMeta(
        id="T22",
        name="Open redirect via trusted domain",
        threat="Link routed through google.com/url?q= to disguise the real destination. "
               "The gateway sees google.com (top reputation) and may not follow the redirect chain.",
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Security Update — Immediate Action Required"
        msg.set_content(f"Please review the security update: {_URL}")
        msg.add_alternative(
            f"<html><body>"
            f"<p>A critical security update requires your attention.</p>"
            f"<p><a href='{_URL}'>Click here to review</a></p>"
            f"</body></html>",
            subtype="html",
        )
        return msg
