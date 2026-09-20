"""Resource-ownership rules for the reference support domain.

Kept beside the domain it describes. ``boundedllm.authz`` holds only the checks
that are true of every deployment: liveness, scope, clearance, and document
readability. Who may touch an account is an application's rule, not the core's.
"""

from boundedllm.models import Principal
from boundedllm.support.models import Account


def can_access_account(principal: Principal, account: Account) -> bool:
    """Tenant match plus either ownership or an explicit support-admin role."""
    return principal.tenant_id == account.tenant_id and (
        principal.subject == account.owner_subject or "support_admin" in principal.roles
    )
