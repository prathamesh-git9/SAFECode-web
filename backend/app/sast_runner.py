"""SAST Runner using Flawfinder for C/C++ code analysis."""

import subprocess
import tempfile
import os
import csv
import json
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Represents a vulnerability found by Flawfinder."""
    line: int
    column: int
    level: str
    category: str
    description: str
    suggestion: str
    cwe_id: str
    snippet: str
    file: str


class FlawfinderRunner:
    """Runner for Flawfinder SAST tool."""

    def __init__(self):
        """Initialize Flawfinder runner."""
        self.tool_name = "flawfinder"
        self.check_availability()

    def check_availability(self) -> bool:
        """Check if Flawfinder is available."""
        try:
            result = subprocess.run(
                [self.tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Flawfinder available: {result.stdout.strip()}")
                return True
            else:
                logger.warning("Flawfinder not available")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("Flawfinder not found. Install with: pip install flawfinder")
            return False

    def run_scan(self, code: str, filename: str = "code.c") -> Tuple[List[Vulnerability], bool]:
        """
        Run Flawfinder scan on the provided code.
        
        Args:
            code: Source code to analyze
            filename: Filename for the code
            
        Returns:
            Tuple of (vulnerabilities, success)
        """
        if not self.check_availability():
            return [], False

        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.c',
                delete=False,
                encoding='utf-8'
            ) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name

            # Run Flawfinder with CSV output
            cmd = [
                self.tool_name,
                "--csv",
                "--context",
                "--dataonly",
                temp_file_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            vulnerabilities = []
            if result.returncode == 0:
                vulnerabilities = self._parse_csv_output(result.stdout, code, filename)
            else:
                logger.error(f"Flawfinder failed: {result.stderr}")

            # Clean up
            os.unlink(temp_file_path)

            return vulnerabilities, True

        except Exception as e:
            logger.error(f"Error running Flawfinder: {e}")
            return [], False

    def _parse_csv_output(self, output: str, code: str, filename: str) -> List[Vulnerability]:
        """Parse Flawfinder CSV output."""
        vulnerabilities = []
        lines = code.split('\n')

        try:
            # Parse CSV output
            csv_reader = csv.reader(output.strip().split('\n'))
            for row in csv_reader:
                if len(row) >= 6:
                    try:
                        line_num = int(row[0])
                        column = int(row[1])
                        level = row[2]
                        category = row[3]
                        description = row[4]
                        suggestion = row[5] if len(row) > 5 else ""

                        # Get code snippet
                        snippet = self._get_snippet(lines, line_num, filename)

                        # Map to CWE
                        cwe_id = self._map_category_to_cwe(category)

                        vuln = Vulnerability(
                            line=line_num,
                            column=column,
                            level=level,
                            category=category,
                            description=description,
                            suggestion=suggestion,
                            cwe_id=cwe_id,
                            snippet=snippet,
                            file=filename
                        )
                        vulnerabilities.append(vuln)

                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error parsing CSV row: {row}, error: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error parsing CSV output: {e}")

        return vulnerabilities

    def _get_snippet(self, lines: List[str], line_num: int, filename: str) -> str:
        """Get code snippet around the vulnerable line."""
        try:
            start_line = max(0, line_num - 2)
            end_line = min(len(lines), line_num + 1)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                line_content = lines[i] if i < len(lines) else ""
                line_number = i + 1
                marker = ">>> " if line_number == line_num else "    "
                snippet_lines.append(f"{marker}{line_number:3d}: {line_content}")
            
            return "\n".join(snippet_lines)
        except Exception as e:
            logger.error(f"Error getting snippet: {e}")
            return f"Line {line_num}: {lines[line_num-1] if line_num <= len(lines) else 'Unknown'}"

    def _map_category_to_cwe(self, category: str) -> str:
        """Map Flawfinder category to CWE ID."""
        mapping = {
            "buffer": "CWE-120",
            "format": "CWE-134",
            "race": "CWE-367",
            "random": "CWE-338",
            "shell": "CWE-78",
            "tempfile": "CWE-377",
            "time": "CWE-367",
            "tob": "CWE-190",
            "untrusted": "CWE-20",
            "xss": "CWE-79"
        }
        return mapping.get(category.lower(), "CWE-20")

    def get_severity_level(self, level: str) -> str:
        """Convert Flawfinder level to severity."""
        level_map = {
            "5": "critical",
            "4": "high", 
            "3": "medium",
            "2": "low",
            "1": "info"
        }
        return level_map.get(level, "medium")


def run_flawfinder_scan(code: str, filename: str = "code.c") -> Tuple[List[Dict], bool]:
    """
    Run Flawfinder scan and return findings in the expected format.
    
    Args:
        code: Source code to analyze
        filename: Filename for the code
        
    Returns:
        Tuple of (findings, success)
    """
    runner = FlawfinderRunner()
    vulnerabilities, success = runner.run_scan(code, filename)
    
    if not success:
        return [], False

    # Convert to expected format
    findings = []
    for vuln in vulnerabilities:
        finding = {
            "id": f"flawfinder_{vuln.line}_{vuln.column}",
            "cwe_id": vuln.cwe_id,
            "title": f"{vuln.category.title()} vulnerability",
            "severity": runner.get_severity_level(vuln.level),
            "status": "ACTIVE",
            "line": vuln.line,
            "snippet": vuln.snippet,
            "file": vuln.file,
            "tool": "flawfinder",
            "confidence": "HIGH",
            "suppression_reason": None,
            "context": {
                "category": vuln.category,
                "description": vuln.description,
                "suggestion": vuln.suggestion,
                "level": vuln.level
            }
        }
        findings.append(finding)

    return findings, True
