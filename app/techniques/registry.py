import importlib
import pkgutil
from pathlib import Path

from .base import Technique


# Send order: stealthiest payloads first, loudest / basic-signature last (EICAR).
#
# Rationale: a brand-new external sender that bursts 29 odd messages at one mailbox
# is itself a suspicious pattern. If the gateway degrades the sender's reputation
# mid-run — or the obvious malware (EICAR/macro) trips a block on the sending
# account — that contamination must not reach the subtle techniques. By delivering
# the hard-to-detect vectors FIRST and the loud, definitely-caught ones LAST, each
# subtle technique is measured on its own payload merits before the carrier can
# burn. Combined with paced sending (SEND_INTERVAL/JITTER), this keeps results
# comparable across the whole run. Tune the sequence here.
#
# Tiers (stealth → loud):
#   1. Pure content/URL obfuscation & HTML smuggling — gateway often can't see the payload
#   2. Identity/behaviour tricks (spoofing, BEC, QR, calendar) — no malware bytes
#   3. Evasive / alternative-format attachments (encrypted ZIP, ISO, OneNote, PDF-JS, LNK)
#   4. Known-bad URL reputation + macros + EICAR signature — definitely flagged, sent last
SEND_ORDER = [
    "T16", "T17", "T29", "T27", "T26", "T06", "T13", "T07", "T14", "T01",
    "T24", "T22", "T11",                          # tier 1 — obfuscation / smuggling
    "T12", "T23", "T28", "T08",                   # tier 2 — identity / behaviour
    "T18", "T03", "T02", "T04", "T15",            # tier 3a — evasive attachments
    "T20", "T21", "T19", "T25",                   # tier 3b — alt-format malware
    "T10", "T05", "T09",                          # tier 4 — known-bad URL / macro / EICAR
]


def send_rank(technique_id: str) -> int:
    """Position of a technique in the stealth→loud send sequence.

    Unknown IDs sort to the middle so a newly added technique never lands first
    (stealthiest) or last (loudest) by accident."""
    try:
        return SEND_ORDER.index(technique_id)
    except ValueError:
        return len(SEND_ORDER) // 2


def load_all() -> list[Technique]:
    """Auto-discover and instantiate all Technique subclasses in this package."""
    package_dir = Path(__file__).parent
    techniques: list[Technique] = []

    for _, module_name, _ in pkgutil.iter_modules([str(package_dir)]):
        if not module_name.startswith("t"):
            continue
        module = importlib.import_module(f".{module_name}", package=__package__)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, Technique)
                and attr is not Technique
            ):
                techniques.append(attr())

    return sorted(techniques, key=lambda t: t.meta.id)
