"""T18 — Password-protected ZIP (PKZIP traditional encryption, pure Python)."""

import os
import struct
import time
import zlib
from email.message import Message, EmailMessage
from .base import Technique, TechniqueMeta


def _make_encrypted_zip(filename: str, plaintext: bytes, password: bytes) -> bytes:
    """PKZIP traditional encryption — no external dependencies."""

    def _crc_b(b: int, crc: int) -> int:
        return zlib.crc32(bytes([b]), crc) & 0xFFFFFFFF

    def _init(pwd: bytes) -> list:
        k = [305419896, 591751049, 878082192]
        for b in pwd:
            k[0] = _crc_b(b, k[0])
            k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
            k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
            k[2] = _crc_b((k[1] >> 24) & 0xFF, k[2])
        return k

    def _upd(k: list, b: int):
        k[0] = _crc_b(b, k[0])
        k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
        k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
        k[2] = _crc_b((k[1] >> 24) & 0xFF, k[2])

    def _enc(k: list, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            t = (k[2] | 2) & 0xFFFF
            ks = ((t * (t ^ 1)) >> 8) & 0xFF
            out.append(ks ^ b)
            _upd(k, b)
        return bytes(out)

    compressed = zlib.compress(plaintext, 9)[2:-4]
    file_crc = zlib.crc32(plaintext) & 0xFFFFFFFF

    now = time.localtime()
    dos_time = (now.tm_hour << 11) | (now.tm_min << 5) | (now.tm_sec // 2)
    dos_date = ((now.tm_year - 1980) << 9) | (now.tm_mon << 5) | now.tm_mday

    # 12-byte header: 11 random + check byte = high byte of dos_time
    enc_hdr_plain = os.urandom(11) + bytes([(dos_time >> 8) & 0xFF])
    k = _init(password)
    payload = _enc(k, enc_hdr_plain) + _enc(k, compressed)

    fname = filename.encode("utf-8")

    lfh = struct.pack("<4sHHHHHIIIHH",
        b"PK\x03\x04", 20, 0x0001, 8,
        dos_time, dos_date,
        file_crc, len(payload), len(plaintext),
        len(fname), 0) + fname

    cdh = struct.pack("<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02", 0x0314, 20, 0x0001, 8,
        dos_time, dos_date,
        file_crc, len(payload), len(plaintext),
        len(fname), 0, 0, 0, 0, 0x20, 0) + fname

    eocd = struct.pack("<4sHHHHIIH",
        b"PK\x05\x06", 0, 0, 1, 1,
        len(cdh), len(lfh) + len(payload), 0)

    return lfh + payload + cdh + eocd


_CONTENT = (
    "<html><body><h1>MAILPROBE T18 — Password-Protected ZIP</h1>"
    "<p>This file was delivered inside an encrypted ZIP archive.</p>"
    "<p>The gateway could not inspect this content.</p></body></html>"
)


class T18(Technique):
    meta = TechniqueMeta(
        id="T18",
        name="Password-protected ZIP",
        threat="ZIP with traditional PKZIP encryption — the gateway cannot scan the contents. "
               "The password is sent in the email body. Active vector in 90%+ of ransomware campaigns.",
        expected_attachments=["document.zip"],
    )

    def build_message(self) -> Message:
        zip_bytes = _make_encrypted_zip("document.html", _CONTENT.encode(), b"infected")

        msg = EmailMessage()
        msg["Subject"] = "Secure Document — Password: infected"
        msg.set_content(
            "Please find the secure document attached.\n"
            "Archive password: infected\n\n"
            "Open the ZIP and enter the password to access the document."
        )
        msg.add_attachment(
            zip_bytes,
            maintype="application",
            subtype="zip",
            filename="document.zip",
        )
        return msg
