"""
SLOP Auditor CLI - Python wrapper for @slop/auditor

This module provides a Python interface to the slop-auditor npm package.
It requires Node.js to be installed on the system.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def _check_node() -> bool:
    """Check if Node.js is installed."""
    return shutil.which("node") is not None


def _check_npm() -> bool:
    """Check if npm is installed."""
    return shutil.which("npm") is not None


def _check_slop_auditor() -> bool:
    """Check if slop-auditor is installed globally."""
    return shutil.which("slop-auditor") is not None


def _get_npx_cmd() -> List[str]:
    """Get the npx command to run slop-auditor."""
    if _check_slop_auditor():
        return ["slop-auditor"]
    return ["npx", "@slop/auditor"]


def _run_command(args: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    cmd = _get_npx_cmd() + args

    if capture_output:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=(sys.platform == "win32")
        )
    else:
        return subprocess.run(
            cmd,
            shell=(sys.platform == "win32")
        )


class SlopAuditor:
    """
    Python interface to the SLOP Auditor security scanner.

    Example usage:
        auditor = SlopAuditor()
        result = auditor.scan("./my-project")
        print(f"Found {len(result['secrets'])} secrets")
    """

    def __init__(self):
        """Initialize the SLOP Auditor."""
        if not _check_node():
            raise RuntimeError(
                "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org"
            )

    def scan(self, path: str = ".", output_json: bool = True) -> Dict[str, Any]:
        """
        Scan a directory for security issues.

        Args:
            path: Directory path to scan (default: current directory)
            output_json: Return results as JSON dict (default: True)

        Returns:
            Dict containing scan results with keys:
            - secrets: List of found secrets
            - packages: List of package vulnerabilities
            - sastFindings: List of SAST findings
            - discoveredServices: List of discovered services
            - toolsUsed: List of security tools used
        """
        args = ["scan", path]
        if output_json:
            args.append("--json")

        result = _run_command(args, capture_output=output_json)

        if output_json and result.returncode in (0, 1, 2):
            # Parse JSON output (skip header lines)
            lines = result.stdout.strip().split("\n")
            for i, line in enumerate(lines):
                if line.strip().startswith("{"):
                    json_str = "\n".join(lines[i:])
                    return json.loads(json_str)

        return {"error": result.stderr, "returncode": result.returncode}

    def scan_aws(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        services: Optional[List[str]] = None,
        output_json: bool = True
    ) -> Dict[str, Any]:
        """
        Scan AWS infrastructure for security issues.

        Args:
            region: AWS region to scan (default: us-east-1)
            profile: AWS profile name (optional)
            services: List of services to scan (default: all)
            output_json: Return results as JSON dict (default: True)

        Returns:
            Dict containing AWS scan results with keys:
            - findings: List of security findings
            - summary: Count by severity
            - scannedServices: List of services scanned
            - errors: List of scan errors
        """
        args = ["aws", "--region", region]

        if profile:
            args.extend(["--profile", profile])

        if services:
            args.extend(["--services", ",".join(services)])

        if output_json:
            args.append("--json")

        result = _run_command(args, capture_output=output_json)

        if output_json and result.returncode in (0, 1, 2):
            lines = result.stdout.strip().split("\n")
            for i, line in enumerate(lines):
                if line.strip().startswith("{"):
                    json_str = "\n".join(lines[i:])
                    return json.loads(json_str)

        return {"error": result.stderr, "returncode": result.returncode}

    def init(self, path: str = ".") -> bool:
        """
        Initialize SLOP Auditor configuration in a directory.

        Args:
            path: Directory path (default: current directory)

        Returns:
            True if initialization was successful
        """
        result = _run_command(["init", path])
        return result.returncode == 0

    def serve(self, port: int = 3000) -> None:
        """
        Start the SLOP server.

        Args:
            port: Server port (default: 3000)
        """
        os.environ["SLOP_PORT"] = str(port)
        _run_command(["serve"])

    def visualizer(self, port: int = 8080) -> None:
        """
        Start the 3D visualizer server.

        Args:
            port: Visualizer port (default: 8080)
        """
        os.environ["VISUALIZER_PORT"] = str(port)
        _run_command(["visualizer"])


# Convenience functions

def scan(path: str = ".", output_json: bool = True) -> Dict[str, Any]:
    """
    Scan a directory for security issues.

    Convenience function for SlopAuditor().scan()
    """
    return SlopAuditor().scan(path, output_json)


def scan_aws(
    region: str = "us-east-1",
    profile: Optional[str] = None,
    services: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Scan AWS infrastructure for security issues.

    Convenience function for SlopAuditor().scan_aws()
    """
    return SlopAuditor().scan_aws(region, profile, services)


def main() -> int:
    """
    Main CLI entry point.

    Passes all arguments to the underlying slop-auditor command.
    """
    if not _check_node():
        print("Error: Node.js is not installed.")
        print("Please install Node.js 18+ from https://nodejs.org")
        return 1

    # Pass through all arguments to slop-auditor
    args = sys.argv[1:]
    result = _run_command(args)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
