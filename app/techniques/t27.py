"""T27 — Dynamic URL assembled from data-attributes (evades static scanners)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


class T27(Technique):
    meta = TechniqueMeta(
        id="T27",
        name="Dynamic URL via data-attributes",
        threat="The href attribute is empty; JavaScript assembles the real URL from data-* attributes on click. "
               "Static scanners find no URL in the HTML.",
    )

    def build_message(self) -> Message:
        html = (
            "<html><body>"
            "<p>Please review the important security update:</p>"
            "<a href='#' "
            "   data-scheme='https' "
            "   data-host='eicar' "
            "   data-tld='org' "
            "   onclick=\"this.href=this.dataset.scheme+'://'+this.dataset.host+'.'+this.dataset.tld;\">"
            "View Security Update"
            "</a>"
            "</body></html>"
        )
        msg = EmailMessage()
        msg["Subject"] = "Important Security Update"
        msg.set_content("Please review the important security update in the HTML version of this email.")
        msg.add_alternative(html, subtype="html")
        return msg
