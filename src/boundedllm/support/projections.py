"""Purpose-specific output projections prevent unnecessary data reaching the model."""

from boundedllm.support.models import Account


def account_summary(account: Account) -> dict:
    # Ownership, tenant identifiers, and contact details never enter tool output.
    return {"status": account.status, "currency": account.currency, "fee_cents": account.fee_cents}
