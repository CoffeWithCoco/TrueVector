import io
import zipfile
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from .base import Technique, TechniqueMeta

# Minimal Word Open XML structure — inert, no real macro, just the file format skeleton
_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>"""

_DOCUMENT_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>MailProbe T05 — Macro test (inert). Enable macros to view content.</w:t></w:r></w:p>
  </w:body>
</w:document>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>"""


def _build_docm() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("_rels/.rels", _RELS)
        zf.writestr("word/document.xml", _DOCUMENT_XML)
    return buf.getvalue()


class T05OfficeMacro(Technique):
    meta = TechniqueMeta(
        id="T05",
        name="Office macro document (.docm)",
        threat="Macro execution — .docm is a classic vector for delivering malware via Office macros.",
        expected_attachments=["report.docm"],
    )

    def build_message(self) -> Message:
        msg = MIMEMultipart()
        msg["Subject"] = "Q2 report — enable macros to view the content"
        msg.attach(MIMEText("Open the attachment and enable macros to view the report.", "plain", "utf-8"))

        att = MIMEApplication(_build_docm(), _subtype="vnd.ms-word.document.macroEnabled.12")
        att.add_header("Content-Disposition", "attachment", filename="report.docm")
        msg.attach(att)
        return msg
