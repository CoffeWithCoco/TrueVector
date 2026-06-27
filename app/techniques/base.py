from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.message import Message


@dataclass
class RuntimeContext:
    """Deploy-specific values injected at send time (see Settings → Payload hosting).

    Techniques that deliver their payload through infrastructure you control read
    these. Empty strings mean "not configured" — such techniques are gated in the UI
    and skipped by the worker so they never send a broken placeholder.
    """
    web_base_url: str = ""        # base URL of a server you host (landing / HTML-smuggling page)
    cloud_payload_url: str = ""   # full URL to a payload on trusted cloud storage (Azure Blob / S3)


@dataclass
class TechniqueMeta:
    id: str
    name: str
    threat: str
    expected_attachments: list[str] = field(default_factory=list)
    expected_images: bool = False
    needs_web: bool = False     # requires external web server to deliver full payload
    # If set, names the RuntimeContext / Config field this technique needs to run
    # (e.g. "web_base_url"). Used to gate the technique in the UI and worker.
    requires: str | None = None
    # If set, sender.py uses this as the From display name instead of config.from_name.
    # Enables real display-name spoofing while keeping the authenticated address
    # (so the provider doesn't reject the message). Used by T12.
    spoof_from_name: str | None = None


class Technique(ABC):
    meta: TechniqueMeta

    @abstractmethod
    def build_message(self) -> Message:
        """Return a fully-formed Message ready to send.
        Do NOT set From, To, Subject or X-Validator-ID — sender.py handles those."""
        ...

    def render(self, ctx: RuntimeContext | None = None) -> Message:
        """Build the message for sending, substituting deploy-specific values.

        Default: ignore ctx and return build_message() (used for previews and by the
        26 self-contained techniques). Techniques that need hosted infrastructure
        override this to inject ctx values."""
        return self.build_message()
