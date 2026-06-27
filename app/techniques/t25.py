"""T25 — Windows shortcut (.lnk) inside ZIP."""

import io
import struct
import zipfile
from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


def _make_lnk() -> bytes:
    """Minimal Windows Shell Link (.lnk) file — inert, no CommandLineArguments."""
    # LNK HeaderSize (76) + CLSID + LinkFlags + FileAttributes + timestamps + ...
    buf = bytearray(76)
    struct.pack_into("<I", buf, 0, 76)          # HeaderSize
    # LinkCLSID: 00021401-0000-0000-C000-000000000046
    buf[4:20] = bytes([
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ])
    struct.pack_into("<I", buf, 20, 0x00000001)  # LinkFlags: HasLinkTargetIDList
    struct.pack_into("<I", buf, 24, 0x00000020)  # FileAttributes: FILE_ATTRIBUTE_ARCHIVE
    return bytes(buf)


class T25(Technique):
    meta = TechniqueMeta(
        id="T25",
        name="LNK shortcut in ZIP",
        threat="A Windows .lnk shortcut with CommandLineArguments executes arbitrary commands. "
               "Packed in a ZIP to evade filters on direct .lnk attachments. Very common post-macros.",
        expected_attachments=["documents.zip"],
    )

    def build_message(self) -> Message:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("Open_Document.lnk", _make_lnk())
        zip_bytes = buf.getvalue()

        msg = EmailMessage()
        msg["Subject"] = "Documents Package — Review Required"
        msg.set_content("Please find the requested documents attached.")
        msg.add_attachment(
            zip_bytes,
            maintype="application",
            subtype="zip",
            filename="documents.zip",
        )
        return msg
