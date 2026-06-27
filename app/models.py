from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Config(Base):
    __tablename__ = "config"

    id = Column(Integer, primary_key=True, default=1)
    # Sender
    smtp_host = Column(String(255))
    smtp_port = Column(Integer, default=587)
    smtp_user = Column(String(255))
    smtp_pass = Column(String(255))
    from_domain = Column(String(255))
    from_name = Column(String(255), default="Security Validator")
    # Send pacing — seconds to wait between each real send, plus random jitter (±)
    # so the run doesn't look like a cron. Spacing the sends keeps the sender's
    # reputation stable across the whole campaign so per-technique verdicts stay
    # comparable (don't let the carrier burn mid-run). 0 = burst (send back-to-back).
    send_interval = Column(Integer, default=90)
    send_jitter = Column(Integer, default=30)
    # Control canaries — benign, payload-free emails sent interleaved with the
    # techniques. They probe the *sender's* reputation, not any gateway control:
    # if they start landing in Junk/blocked mid-run, the carrier degraded and later
    # technique verdicts are suspect. Used by the contamination detector.
    canaries_enabled = Column(Boolean, default=True)
    canary_every = Column(Integer, default=7)   # send a canary every N techniques
    # Target mailbox — address where test emails are delivered and read back via API
    target_email = Column(String(255))
    # Which backend reads the mailbox back: imap | microsoft | google
    reader_backend = Column(String(20), default="imap")
    # IMAP credentials for reading back test emails
    imap_host = Column(String(255))
    imap_port = Column(Integer, default=993)
    imap_user = Column(String(255))
    imap_pass = Column(String(255))
    # Microsoft Graph (app-only / client credentials) — corporate M365
    ms_tenant_id = Column(String(255))
    ms_client_id = Column(String(255))
    ms_client_secret = Column(String(255))
    # Google Gmail API (service account with domain-wide delegation) — Workspace
    google_sa_json = Column(Text)
    # Payload hosting — infrastructure the operator controls, used by techniques
    # that deliver their payload externally (see Settings → Payload hosting).
    web_base_url = Column(String(255))       # T17 (HTML smuggling page), T28 (QR target)
    cloud_payload_url = Column(String(500))  # T29 (EICAR on trusted cloud storage)


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    selected_techniques = Column(Text, nullable=True)   # JSON list: ["T01","T03",...]
    status = Column(String(50), default="pending")       # pending|running|done|error
    score = Column(Float, nullable=True)
    # Carrier (sender-reputation) health derived from control canaries:
    # stable | degraded | unknown. "degraded" means some technique verdicts may
    # reflect a burned sender rather than the payload (see Result.carrier_suspect).
    carrier_status = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)

    results = relationship("Result", back_populates="campaign", cascade="all, delete-orphan")


class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    technique_id = Column(String(10), nullable=False)
    technique_name = Column(String(255))
    threat = Column(String(500))                          # denormalized for reports
    validator_id = Column(String(64), unique=True, index=True)

    # Layer 1
    placement = Column(String(20), default="MISSING")     # INBOX | JUNK | MISSING

    # Layer 2 — gateway verdict
    scl = Column(Integer, nullable=True)
    gateway_category = Column(String(50), nullable=True)  # PHSH|MALW|BULK|SPOOF|NONE
    spf = Column(String(20), nullable=True)
    dkim = Column(String(20), nullable=True)
    dmarc = Column(String(20), nullable=True)
    gateway_raw = Column(Text, nullable=True)             # JSON

    # Layer 3 — body
    links_rewritten = Column(Boolean, default=False)
    banner_injected = Column(Boolean, default=False)
    body_modified = Column(Boolean, default=False)

    # Layer 4 — attachments
    attachments_stripped = Column(Boolean, default=False)
    attachment_names_rx = Column(Text, nullable=True)     # JSON list

    # Layer 5 — images
    images_present = Column(Boolean, default=False)
    images_stripped = Column(Boolean, default=False)
    images_proxied = Column(Boolean, default=False)

    message_id = Column(String(255))
    delivered_at = Column(DateTime, nullable=True)

    # Set by the contamination detector: True when this technique was sent after the
    # carrier (sender reputation) degraded mid-run, so its verdict may reflect the
    # burned sender rather than its payload. Read alongside Campaign.carrier_status.
    carrier_suspect = Column(Boolean, default=False)

    campaign = relationship("Campaign", back_populates="results")
