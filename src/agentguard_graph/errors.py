"""Application exceptions."""


class AgentGuardError(Exception):
    """Base exception for expected AgentGuard Graph failures."""


class EvidenceLoadError(AgentGuardError):
    """Raised when evidence cannot be loaded or parsed."""


class ValidationFailure(AgentGuardError):
    """Raised when evidence validation has fatal errors."""
