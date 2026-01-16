"""Manifest generator for run metadata."""

import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ManifestGenerator:
    """Generates run manifest with hashes, versions, and metadata."""

    def __init__(
        self, pcap_path: Path, run_dir: Path, git_info: dict[str, str], config: dict[str, Any]
    ):
        """Initialize manifest generator.

        Args:
            pcap_path: Path to input PCAP file
            run_dir: Output directory for this run
            git_info: Git commit and branch information
            config: Detector configuration used
        """
        self.pcap_path = Path(pcap_path)
        self.run_dir = Path(run_dir)
        self.git_info = git_info
        self.config = config

    def generate(self) -> dict[str, Any]:
        """Generate run manifest.

        Returns:
            Manifest dictionary
        """
        manifest = {
            "run_timestamp": self.run_dir.name,
            "pcap_file": str(self.pcap_path.name),
            "pcap_hash": self._compute_file_hash(self.pcap_path),
            "git_commit": self.git_info.get("commit", "unknown"),
            "git_branch": self.git_info.get("branch", "unknown"),
            "tool_versions": self._get_tool_versions(),
            "config": self.config,
            "outputs": self._list_outputs(),
        }
        return manifest

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file.

        Args:
            file_path: Path to file

        Returns:
            SHA256 hash hex string
        """
        if not file_path.exists():
            return "file_not_found"

        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to compute hash for {file_path}: {e}")
            return "hash_error"

    def _get_tool_versions(self) -> dict[str, str]:
        """Get versions of tools used.

        Returns:
            Dictionary of tool names to versions
        """
        versions = {}

        # Python version
        try:
            import sys

            versions["python"] = sys.version.split()[0]
        except Exception:
            versions["python"] = "unknown"

        # Try to get Zeek version (if available)
        try:
            result = subprocess.run(
                ["zeek", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                versions["zeek"] = result.stdout.strip().split("\n")[0]
            else:
                versions["zeek"] = "not_available"
        except Exception:
            versions["zeek"] = "not_available"

        # Try to get Suricata version (if available)
        try:
            result = subprocess.run(
                ["suricata", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                versions["suricata"] = result.stdout.strip().split("\n")[0]
            else:
                versions["suricata"] = "not_available"
        except Exception:
            versions["suricata"] = "not_available"

        return versions

    def _list_outputs(self) -> dict[str, str]:
        """List output files and their hashes.

        Returns:
            Dictionary of output file names to hashes
        """
        outputs = {}

        # Check for common output files
        output_files = [
            "events.parquet",
            "case_report.md",
            "agent_trace.jsonl",
        ]

        for filename in output_files:
            file_path = self.run_dir / filename
            if file_path.exists():
                outputs[filename] = self._compute_file_hash(file_path)

        return outputs
