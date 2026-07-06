"""post_round hook — fired after each CombatPair round."""

from __future__ import annotations

from ..runner import RunContext

ENTROPY_THRESHOLD = 1.5
DIVERSITY_RETRY_TRIGGER = "diversity_retry_needed"


def entropy_guard(ctx: RunContext) -> None:
    """
    Check Shannon entropy of CWE categories used so far.

    If entropy < 1.5 bits (attacks are too homogeneous), set a flag
    that the next round's Breaker should force CWE diversity rotation.
    """
    if not ctx.round_attacks:
        return

    import math
    from collections import Counter

    cwes = [a.cwe for a in ctx.round_attacks]
    freq = Counter(cwes)
    total = len(cwes)
    if total < 3:
        return

    entropy = -sum((v / total) * math.log2(v / total) for v in freq.values())
    ctx.metadata["last_round_entropy"] = round(entropy, 3)

    if entropy < ENTROPY_THRESHOLD:
        ctx.metadata[DIVERSITY_RETRY_TRIGGER] = True
    else:
        ctx.metadata.pop(DIVERSITY_RETRY_TRIGGER, None)
