"""A request-local budget bounds agent loops independently of shared tenant quotas."""

from dataclasses import dataclass

from agentguard.errors import LimitExceeded


@dataclass
class Budget:
    model_calls: int
    tool_calls: int
    documents: int

    def spend(self, dimension: str, amount: int = 1) -> None:
        if dimension not in {"model_calls", "tool_calls", "documents"} or amount < 0:
            raise ValueError("invalid budget dimension")
        remaining = getattr(self, dimension)
        if remaining < amount:
            raise LimitExceeded("REQUEST_BUDGET")
        setattr(self, dimension, remaining - amount)
