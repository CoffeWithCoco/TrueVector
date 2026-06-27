"""T19 — ISO disk image (.iso)."""

from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta

_SECTOR = 2048  # ISO9660 sector size


def _make_iso() -> bytes:
    """Minimal valid ISO9660 image with correct magic bytes at sector 16."""
    iso = bytearray(_SECTOR * 18)

    # Primary Volume Descriptor at sector 16 (offset 32768)
    pvd = 16 * _SECTOR
    iso[pvd]       = 0x01           # Type: Primary Volume Descriptor
    iso[pvd+1:pvd+6] = b"CD001"    # Standard Identifier
    iso[pvd+6]     = 0x01           # Version
    vol_id = b"MAILPROBE".ljust(32)
    iso[pvd+40:pvd+72] = vol_id     # Volume Identifier

    # Volume Descriptor Set Terminator at sector 17
    vdst = 17 * _SECTOR
    iso[vdst]       = 0xFF
    iso[vdst+1:vdst+6] = b"CD001"
    iso[vdst+6]     = 0x01

    return bytes(iso)


class T19(Technique):
    meta = TechniqueMeta(
        id="T19",
        name="ISO disk image (.iso)",
        threat="Windows 10+ mounts ISO files on double-click without extraction. "
               "Many gateways don't scan the inner contents of disk images. "
               "Dominant Emotet/Qakbot vector in 2021-2022.",
        expected_attachments=["installer.iso"],
    )

    def build_message(self) -> Message:
        msg = EmailMessage()
        msg["Subject"] = "Software Package — Installation Files Attached"
        msg.set_content("Please find the software installation image attached.")
        msg.add_attachment(
            _make_iso(),
            maintype="application",
            subtype="octet-stream",
            filename="installer.iso",
        )
        return msg
