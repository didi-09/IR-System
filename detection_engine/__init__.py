# Detection Engine Package
"""
Bayoumy's Detection Engine - Security Incident Detection & Response System

This package contains:
- log_parser.py: Parses authentication logs
- detection_rules.py: Implements detection rules (brute force, etc.)
- containment.py: Automated response actions (iptables, kill)
- detection_agent.py: Main agent that orchestrates everything
"""

from .log_parser import AuthLogParser
from .detection_rules import DetectionEngine, DetectionRule, BruteForceRule
from .containment import ContainmentActions
from .detection_agent import DetectionAgent

__all__ = [
    'AuthLogParser',
    'DetectionEngine',
    'DetectionRule',
    'BruteForceRule',
    'ContainmentActions',
    'DetectionAgent'
]

