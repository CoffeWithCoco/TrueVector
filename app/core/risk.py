"""
Risk classification engine: per-technique profiles, attack chain detection,
remediation guidance.
"""

from dataclasses import dataclass, field

# ── Risk levels ───────────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
PASS     = "PASS"

RISK_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, PASS: 0}

# Tuned for a light-themed PDF: dark enough to read as text on white AND to carry
# white text when used as a filled badge.
RISK_COLOR_PDF = {
    CRITICAL: (220, 38,  38),   # red-600
    HIGH:     (234, 88,  12),   # orange-600
    MEDIUM:   (180, 130, 9),    # amber-700
    LOW:      (37,  99,  235),  # blue-600
    PASS:     (5,   150, 105),  # emerald-600
}

# ── Per-technique profile ─────────────────────────────────────────────────────

@dataclass
class TechProfile:
    id: str
    category: str
    inbox_risk: str     # risk when technique reaches INBOX
    junk_risk: str      # risk when technique reaches JUNK
    mitre: str


PROFILES: dict[str, TechProfile] = {p.id: p for p in [
    TechProfile("T01", "Content evasion",         HIGH,     LOW,    "T1566.001"),
    TechProfile("T02", "Attachment delivery",     HIGH,     MEDIUM, "T1566.001"),
    TechProfile("T03", "Attachment delivery",     MEDIUM,   LOW,    "T1566.001"),
    TechProfile("T04", "Script execution",        CRITICAL, MEDIUM, "T1566.001 / T1059"),
    TechProfile("T05", "Office macro",            CRITICAL, MEDIUM, "T1566.001 / T1204.002"),
    TechProfile("T06", "URL obfuscation",         HIGH,     LOW,    "T1566.002"),
    TechProfile("T07", "URL obfuscation",         HIGH,     LOW,    "T1566.002"),
    TechProfile("T08", "Calendar delivery",       MEDIUM,   LOW,    "T1566.001"),
    TechProfile("T09", "AV evasion",              CRITICAL, HIGH,   "T1027 / T1059"),
    TechProfile("T10", "URL reputation",          MEDIUM,   LOW,    "T1566.002"),
    TechProfile("T11", "External beaconing",      MEDIUM,   LOW,    "T1566.001 / T1071"),
    TechProfile("T12", "Identity spoofing",       CRITICAL, MEDIUM, "T1566.002 / T1598"),
    TechProfile("T13", "URL obfuscation",         HIGH,     LOW,    "T1566.002"),
    TechProfile("T14", "URL analysis evasion",    LOW,      PASS,   "T1566.002"),
    TechProfile("T15", "Script execution",        HIGH,     MEDIUM, "T1059 / T1027"),
    TechProfile("T16", "HTML smuggling",          CRITICAL, HIGH,   "T1027.006 / T1566.001"),
    TechProfile("T17", "HTML smuggling",          CRITICAL, HIGH,   "T1027.006 / T1566.002"),
    TechProfile("T18", "Encrypted delivery",      HIGH,     MEDIUM, "T1566.001 / T1027"),
    TechProfile("T19", "Disk image",              HIGH,     MEDIUM, "T1566.001 / T1204.002"),
    TechProfile("T20", "Office alternative",      CRITICAL, HIGH,   "T1566.001 / T1204.002"),
    TechProfile("T21", "Malicious PDF",           HIGH,     MEDIUM, "T1566.001 / T1059"),
    TechProfile("T22", "Open redirect",           HIGH,     LOW,    "T1566.002 / T1598"),
    TechProfile("T23", "BEC / Fraud",             CRITICAL, MEDIUM, "T1566.002 / T1585"),
    TechProfile("T24", "MIME evasion",            MEDIUM,   LOW,    "T1027 / T1566.001"),
    TechProfile("T25", "LNK dropper",             CRITICAL, HIGH,   "T1566.001 / T1204.002"),
    TechProfile("T26", "URL obfuscation",         HIGH,     LOW,    "T1566.002 / T1027"),
    TechProfile("T27", "Dynamic URL obfuscation", HIGH,     LOW,    "T1566.002 / T1059"),
    TechProfile("T28", "QR phishing",             HIGH,     LOW,    "T1566.002"),
    TechProfile("T29", "Trusted-host delivery",   CRITICAL, HIGH,   "T1566.002 / T1102"),
]}


def result_risk(result) -> str:
    """Compute the effective risk for a single Result row."""
    profile = PROFILES.get(result.technique_id)
    if not profile:
        return LOW
    if result.placement == "INBOX":
        return profile.inbox_risk
    if result.placement == "JUNK":
        return profile.junk_risk
    return PASS  # MISSING = blocked


# ── Attack chain definitions ──────────────────────────────────────────────────

@dataclass
class AttackChain:
    id: str
    name: str
    triggers: list[str]     # technique IDs that can activate this chain
    min_inbox: int           # minimum of triggers that must be in INBOX
    severity: str
    description: str
    impact: str
    remediation: list[str]
    mitre: str


CHAINS: list[AttackChain] = [
    AttackChain(
        id="AC-01",
        name="Phishing — Credential Theft",
        triggers=["T06", "T07", "T12", "T13", "T22", "T26", "T27"],
        min_inbox=2,
        severity=CRITICAL,
        description=(
            "Multiple URL-obfuscation and identity-spoofing techniques reach the inbox. "
            "An attacker can send emails imitating corporate login pages (O365, VPN, HR "
            "portals) with URLs that bypass the gateway's reputation analysis and are "
            "visually indistinguishable to the user."
        ),
        impact=(
            "Theft of corporate credentials, session tokens, and initial access to "
            "cloud/SaaS environments. Common entry point for APT intrusions and ransomware."
        ),
        remediation=[
            "Configure DMARC with a p=reject policy and continuous monitoring",
            "Enable Safe Links / URL Defense with real-time analysis and sandbox detonation",
            "Deploy phishing-resistant MFA (FIDO2/passkeys) on all critical access",
            "Run security-awareness training with quarterly phishing simulations",
            "Enable 'Impersonation Protection' on the gateway for key domains and executives",
        ],
        mitre="T1566.001, T1566.002, T1598.003",
    ),
    AttackChain(
        id="AC-02",
        name="Malware / RAT Deployment",
        triggers=["T04", "T05", "T09", "T15", "T16", "T19", "T20", "T21", "T25", "T29"],
        min_inbox=1,
        severity=CRITICAL,
        description=(
            "At least one executable-payload delivery mechanism reaches the inbox without "
            "being blocked or flagged. This lets an attacker deliver implants, RATs or "
            "droppers that run directly on the target's endpoint without the gateway "
            "intercepting them."
        ),
        impact=(
            "Persistent remote access to the endpoint, data theft, lateral movement "
            "across the corporate network, pivot toward Active Directory or cloud resources."
        ),
        remediation=[
            "Enable dynamic detonation sandbox for all attachments (ATP / Defender for O365)",
            "Block high-risk extensions: .iso, .one, .lnk, .vbs, .js, .hta, .docm, .xlsm",
            "Enable Exploit Guard / Attack Surface Reduction rules on endpoints",
            "Deploy EDR with behavioral detection to cover post-delivery execution",
            "Audit and restrict Office macro execution via Group Policy",
        ],
        mitre="T1566.001, T1204.002, T1059, T1027",
    ),
    AttackChain(
        id="AC-03",
        name="Ransomware Delivery",
        triggers=["T02", "T18", "T19", "T25"],
        min_inbox=1,
        severity=HIGH,
        description=(
            "Attachment packaging and encryption techniques (password-protected ZIP, ISO, "
            "LNK) reach the inbox. These are the most common delivery vectors in ransomware "
            "campaigns (LockBit, BlackCat, Cl0p) because they bypass the gateway's content "
            "analysis."
        ),
        impact=(
            "Encryption of corporate data, double extortion (encryption + exfiltration), "
            "operational shutdown. Average cost per incident: $4.5M (IBM 2024)."
        ),
        remediation=[
            "Block or quarantine password-protected .zip, .iso, .img files without exception",
            "Implement sandbox rules that detect PKZIP with the encryption flag set",
            "Restrict execution of email-downloaded files via AppLocker/WDAC",
            "Segment networks and apply least privilege to limit blast radius",
        ],
        mitre="T1566.001, T1027, T1486",
    ),
    AttackChain(
        id="AC-04",
        name="Business Email Compromise (BEC)",
        triggers=["T12", "T23"],
        min_inbox=1,
        severity=HIGH,
        description=(
            "Display-name spoofing and/or Reply-To manipulation reach the inbox without a "
            "warning. An attacker can impersonate executives or vendors to request "
            "fraudulent transfers, bank-detail changes, or access to sensitive information."
        ),
        impact=(
            "Direct financial fraud, average loss of $125,000 per BEC incident (FBI IC3 2023), "
            "theft of confidential information, reputational damage."
        ),
        remediation=[
            "Enable 'External sender' and 'Impersonation Alert' warnings on the gateway",
            "Configure rules that flag emails whose Reply-To differs from the From domain",
            "Implement an out-of-band verification process for transfers and bank changes",
            "Enforce strict DMARC/DKIM/SPF for owned domains",
        ],
        mitre="T1566.002, T1585, T1534",
    ),
    AttackChain(
        id="AC-05",
        name="C2 Beaconing / Exfiltration",
        triggers=["T10", "T11", "T16", "T17"],
        min_inbox=1,
        severity=MEDIUM,
        description=(
            "External-resource techniques (hotlinked images, low-reputation URLs, external "
            "payloads) reach the client. An attacker can use this to confirm email delivery, "
            "identify active victims (beaconing), or establish a C2 channel."
        ),
        impact=(
            "Identification of active targets, infrastructure fingerprinting, and "
            "establishment of a covert C2 channel within legitimate HTTP/HTTPS traffic."
        ),
        remediation=[
            "Enable external image/resource proxying on the gateway (URL rewriting)",
            "Deploy web content filtering with SSL inspection at the perimeter",
            "Configure DNS filtering to block malicious-category domains",
            "Review and harden Safe Attachments and Safe Links policies",
        ],
        mitre="T1071.003, T1566.001, T1041",
    ),
    AttackChain(
        id="AC-06",
        name="Full Gateway Evasion",
        triggers=["T01", "T06", "T07", "T15", "T24", "T26", "T27"],
        min_inbox=3,
        severity=HIGH,
        description=(
            "Multiple content-obfuscation and analysis-evasion techniques reach the inbox "
            "simultaneously. This indicates the gateway does not perform deep content "
            "inspection or multi-layer decoding, leaving wide room for a sophisticated "
            "attacker to maneuver."
        ),
        impact=(
            "Broad attack surface: any payload can reach the target with enough obfuscation. "
            "Enables persistent covert operations."
        ),
        remediation=[
            "Upgrade the gateway to a version with a next-generation analysis engine",
            "Enable exhaustive decoding: base64, HTML entities, CSS analysis, MIME validation",
            "Deploy a sandbox with dynamic analysis and URL rewriting",
            "Review filtering rules — they may be too permissive to avoid false positives",
        ],
        mitre="T1027, T1140, T1036",
    ),
]


def detect_chains(results) -> list[dict]:
    """Return attack chains triggered by the given results."""
    inbox_ids = {r.technique_id for r in results if r.placement == "INBOX"}
    triggered = []
    for chain in CHAINS:
        matching = inbox_ids & set(chain.triggers)
        if len(matching) >= chain.min_inbox:
            triggered.append({
                "chain": chain,
                "triggered_by": sorted(matching),
            })
    return triggered


def overall_risk(results) -> str:
    """Highest risk level across all results."""
    risks = [result_risk(r) for r in results]
    if not risks:
        return PASS
    return max(risks, key=lambda r: RISK_ORDER.get(r, 0))
