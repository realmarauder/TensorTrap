"""Security signatures and patterns for detection."""

from tensortrap.signatures.dangerous_imports import (
    DANGEROUS_FUNCTIONS,
    DANGEROUS_MODULES,
)
from tensortrap.signatures.patterns import SUSPICIOUS_PATTERNS

__all__ = ["DANGEROUS_MODULES", "DANGEROUS_FUNCTIONS", "SUSPICIOUS_PATTERNS"]
