"""
Custom exceptions for AI4SOAR platform.
"""


class AI4SOARException(Exception):
    """Base exception for AI4SOAR platform."""
    pass


class ConfigurationError(AI4SOARException):
    """Raised when there's a configuration error."""
    pass


class KafkaError(AI4SOARException):
    """Raised when Kafka operations fail."""
    pass


class KafkaPublishError(KafkaError):
    """Raised when publishing to Kafka fails."""
    pass


class KafkaConsumeError(KafkaError):
    """Raised when consuming from Kafka fails."""
    pass


class PlaybookError(AI4SOARException):
    """Raised when playbook operations fail."""
    pass


class PlaybookNotFoundError(PlaybookError):
    """Raised when a playbook is not found."""
    pass


class PlaybookExecutionError(PlaybookError):
    """Raised when playbook execution fails."""
    pass


class AlertError(AI4SOARException):
    """Raised when alert operations fail."""
    pass


class AlertNotFoundError(AlertError):
    """Raised when an alert is not found."""
    pass


class ValidationError(AI4SOARException):
    """Raised when input validation fails."""
    pass


class ScenarioError(AI4SOARException):
    """Raised when scenario validation fails."""
    pass


class STIXBuildError(AI4SOARException):
    """Raised when STIX bundle creation fails."""
    pass


class DatabaseError(AI4SOARException):
    """Raised when database operations fail."""
    pass


class LLMUnavailableError(AI4SOARException):
    """Raised when no LLM provider is configured or reachable."""
    pass
