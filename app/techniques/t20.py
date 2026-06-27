"""T20 — OneNote attachment (.one)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


def _make_onenote() -> bytes:
    """Minimal OneNote section file with correct GUID magic header."""
    # File type GUID for .one section: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
    guid = bytes([
        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
        0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
    ])
    buf = bytearray(1024)
    buf[0:16]  = guid
    buf[16:24] = (1024).to_bytes(8, "little")   # cbExpectedFileLength
    buf[24:28] = (0x0000002A).to_bytes(4, "little")  # ffvLastCodeThatWroteToThisFile
    # Embed a label so the gateway can recognise the content
    label = b"MAILPROBE-T20-ONENOTE-TEST"
    buf[64:64+len(label)] = label
    return bytes(buf)


class T20(Technique):
    meta = TechniqueMeta(
        id="T20",
        name="OneNote attachment (.one)",
        threat=".one files can embed executables and clickable scripts. "
               "Massive vector in 2022-2023 after Office macros were blocked by default. "
               "Many gateways don't fully parse the OneNote format.",
        expected_attachments=["Meeting_Notes.one"],
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Meeting Notes — Q4 Strategy Review"
        msg.set_content("Please review the meeting notes from today's session.")
        msg.add_attachment(
            _make_onenote(),
            maintype="application",
            subtype="onenote",
            filename="Meeting_Notes.one",
        )
        return msg
