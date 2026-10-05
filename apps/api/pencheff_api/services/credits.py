"""Credit-metering compatibility for the self-hosted Community Edition.

The Community Edition does not include SaaS billing or a credit ledger. Keep
the shared quota and scan code paths usable without imposing SaaS credit
checks on self-hosted scans.
"""

from typing import Any


async def ai_credit_ok(session: Any, org_id: str) -> bool:
    """Self-hosted scans are not gated by a SaaS credit balance."""
    return True


def is_credit_metered(plan: str) -> bool:
    """No plan is credit-metered in the Community Edition."""
    return False


async def debit_credits(
    session: Any,
    org_id: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    source: str = "",
    ref: str | None = None,
) -> None:
    """Accept the shared SaaS call signature without recording charges."""
    return None
