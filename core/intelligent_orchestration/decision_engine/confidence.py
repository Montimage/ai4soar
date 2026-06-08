"""
Confidence tier classification.

Translates a raw float confidence score into one of three action tiers:

  HIGH   (≥ early_exit_threshold)      → auto-execute after verification
  MEDIUM (≥ low_confidence_threshold)  → human approval required
  LOW    (< low_confidence_threshold)  → human review mandatory; triggers Path D

Thresholds are read from config so operators can tune them per deployment
without touching code.
"""

from core.config import config


def classify(confidence: float) -> str:
    """
    Return "HIGH", "MEDIUM", or "LOW" for a confidence score in [0, 1].

    >>> classify(0.95)
    'HIGH'
    >>> classify(0.70)
    'MEDIUM'
    >>> classify(0.30)
    'LOW'
    """
    if confidence >= config.orchestration.early_exit_threshold:
        return "HIGH"
    if confidence >= config.orchestration.low_confidence_threshold:
        return "MEDIUM"
    return "LOW"
