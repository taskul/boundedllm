"""Typed internal failures map to generic public responses at the API boundary."""


class GuardError(Exception):
    """Carry only a stable reason code; never embed rejected content or credentials."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class Denied(GuardError):
    """A deterministic authorization decision rejected an operation."""


class InvalidToken(GuardError):
    """Identity could not be established."""


class Unavailable(GuardError):
    """A required dependency failed; access must fail closed."""


class LimitExceeded(GuardError):
    """A resource or financial ceiling was reached."""


class Conflict(GuardError):
    """An idempotency identifier was reused for different content."""


class OutputBlocked(GuardError):
    """The complete response failed inspection and must not be released."""
