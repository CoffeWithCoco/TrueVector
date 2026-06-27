"""Carrier (sender-reputation) health assessment via control canaries.

Control canaries are benign, payload-free emails sent interleaved with the
techniques. They don't test any gateway control — they probe the *sender's*
standing. A brand-new sender that bursts ~29 odd messages at one mailbox is a
suspicious pattern in itself, so the gateway can degrade the sender's reputation
*mid-run*; from that point, later technique verdicts may reflect the burned
carrier rather than the payload (the README's "clean the carrier, not the
payload", happening live during one campaign).

By sending plain, innocuous emails at intervals and watching where they land, we
get a control channel: if the canaries stay in the inbox, the carrier held and
all results are trustworthy; if they start going to Junk/blocked partway through,
we know exactly when contamination began and can flag everything sent afterwards.
"""

CANARY_PREFIX = "CANARY"


def is_canary(result) -> bool:
    return (getattr(result, "technique_id", "") or "").startswith(CANARY_PREFIX)


def split_results(results):
    """Partition results into (canaries, techniques), preserving order."""
    canaries, techniques = [], []
    for r in results:
        (canaries if is_canary(r) else techniques).append(r)
    return canaries, techniques


def assess(canaries, technique_rows):
    """Derive carrier health from canary placements.

    Returns (status, suspect_ids):
      status      — "stable" | "degraded" | "unknown"
      suspect_ids — set of Result.id for techniques sent after the carrier
                    degraded (their verdicts may reflect the burned sender).

    Rows are ordered by .id, which equals send order (rows are created and
    committed in the order they're sent). A canary that doesn't cleanly reach the
    inbox marks the onset of degradation; every technique sent after the last
    confirmed-good checkpoint before it is flagged suspect. If even the first
    (baseline) canary is degraded, the sender was already in poor standing and the
    whole run is suspect.
    """
    canaries = sorted(canaries, key=lambda r: r.id)
    technique_rows = sorted(technique_rows, key=lambda r: r.id)

    # Only canaries we could actually locate in the mailbox carry a signal.
    found = [c for c in canaries if c.placement in ("INBOX", "JUNK", "MISSING")]
    if not found:
        return "unknown", set()
    if all(c.placement == "INBOX" for c in found):
        return "stable", set()

    onset = next(c for c in found if c.placement != "INBOX")
    goods_before = [c.id for c in found if c.placement == "INBOX" and c.id < onset.id]
    cutoff = max(goods_before) if goods_before else -1
    suspect = {t.id for t in technique_rows if t.id > cutoff}
    return "degraded", suspect
