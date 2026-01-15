"""
SLOP Auditor - Security Scanner & Audit Pipeline

A security auditor with 3D visualization that scans code repos and AWS
infrastructure for security issues.

This is a Python wrapper for the @slop/auditor npm package.
"""

__version__ = "0.2.0"
__author__ = "slopsecurityadmin"

from .cli import main, scan, scan_aws, SlopAuditor

__all__ = ["main", "scan", "scan_aws", "SlopAuditor", "__version__"]
