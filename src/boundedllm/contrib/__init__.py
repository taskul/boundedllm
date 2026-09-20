"""Ready-made implementations of the core ports for common infrastructure.

Each module here is small on purpose: a port is a narrow contract, and the point
of these is to show that wiring this package to what you already run is an
afternoon, not a migration. Read one before you use it. They are starting points
with the security-relevant decisions marked, not drop-in components you should
trust unexamined.

Every adapter follows the same two rules the ports require:

* **Authorization is enforced inside the query.** Never filter in Python after
  the fact; the rows must never be selected in the first place.
* **Failure raises.** An empty list reads as "nothing matched" and silently
  widens what the model is told, so an internal error must surface as
  ``Unavailable`` and fail the turn closed.

Dependencies are imported lazily so importing ``boundedllm.contrib`` costs
nothing. Install what you use:

    pip install "boundedllm[pgvector]"   # PostgreSQL + pgvector retrieval
    pip install "boundedllm[anthropic]"  # Claude via the official SDK
"""
