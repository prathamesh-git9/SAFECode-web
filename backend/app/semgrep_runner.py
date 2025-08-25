"""Semgrep runner module for SAFECode-Web backend."""

import subprocess
import json
import tempfile
import os
import time
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path

from .config import get_config
from .utils import as_utf8, generate_finding_id, parse_semgrep_severity, parse_semgrep_confidence, extract_cwe_from_message


class SemgrepRunner:
    """Runner for Semgrep static analysis."""
    
    def __init__(self):
        """Initialize Semgrep runner."""
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        
        # Check if semgrep is available
        self.semgrep_available = self._check_semgrep_availability()
    
    def _check_semgrep_availability(self) -> bool:
        """Check if semgrep is available in PATH."""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"Semgrep available: {result.stdout.strip()}")
                return True
            else:
                self.logger.warning(f"Semgrep not available: {result.stderr}")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            self.logger.warning(f"Semgrep not available: {e}")
            return False
    
    def get_semgrep_version(self) -> Optional[str]:
        """Get Semgrep version."""
        if not self.semgrep_available:
            return None
        
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            self.logger.error(f"Error getting Semgrep version: {e}")
        
        return None
    
    def run_scan(self, filename: str, code: str, ruleset: str = "p/security-audit") -> Tuple[List[Dict], bool, bool]:
        """
        Run Semgrep scan on code.
        
        Args:
            filename: Name of the file to scan
            code: Source code to analyze
            ruleset: Semgrep ruleset to use
            
        Returns:
            Tuple[List[Dict], bool, bool]: (findings, timeout, truncated)
        """
        if not self.semgrep_available:
            self.logger.error("Semgrep not available")
            return [], False, False
        
        start_time = time.time()
        timeout_occurred = False
        truncated = False
        
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix=os.path.splitext(filename)[1] or '.c',
                delete=False,
                encoding='utf-8'
            ) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            # Build semgrep command
            cmd = [
                'semgrep',
                '--json',
                '--no-git-ignore',
                '--no-ignore',
                '--config', ruleset,
                '--timeout', str(self.config.semgrep_timeout),
                '--jobs', str(self.config.semgrep_jobs),
                '--max-target-bytes', str(self.config.semgrep_max_target_bytes),
                temp_file_path
            ]
            
            self.logger.debug(f"Running Semgrep: {' '.join(cmd)}")
            
            # Run semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.semgrep_timeout + 5  # Add buffer
            )
            
            duration = time.time() - start_time
            
            # Check for timeout
            if result.returncode == 124 or duration >= self.config.semgrep_timeout:
                timeout_occurred = True
                self.logger.warning(f"Semgrep scan timed out after {duration:.2f}s")
                return [], timeout_occurred, truncated
            
            # Parse results
            findings = self._parse_semgrep_output(result.stdout, result.stderr, filename)
            
            # Check if results were truncated
            if len(findings) >= self.config.semgrep_max_findings:
                truncated = True
                findings = findings[:self.config.semgrep_max_findings]
                self.logger.warning(f"Semgrep results truncated to {self.config.semgrep_max_findings} findings")
            
            self.logger.info(f"Semgrep scan completed in {duration:.2f}s: {len(findings)} findings")
            return findings, timeout_occurred, truncated
            
        except subprocess.TimeoutExpired:
            timeout_occurred = True
            self.logger.error("Semgrep scan timed out")
            return [], timeout_occurred, truncated
            
        except Exception as e:
            self.logger.error(f"Error running Semgrep: {e}")
            return [], timeout_occurred, truncated
            
        finally:
            # Clean up temporary file
            try:
                if 'temp_file_path' in locals():
                    os.unlink(temp_file_path)
            except Exception as e:
                self.logger.warning(f"Error cleaning up temp file: {e}")
    
    def _parse_semgrep_output(self, stdout: str, stderr: str, filename: str) -> List[Dict]:
        """
        Parse Semgrep JSON output.
        
        Args:
            stdout: Semgrep stdout
            stderr: Semgrep stderr
            filename: Original filename
            
        Returns:
            List[Dict]: Parsed findings
        """
        findings = []
        
        try:
            # Parse JSON output
            data = json.loads(stdout)
            
            # Extract results
            results = data.get('results', [])
            
            for result in results:
                finding = self._parse_finding(result, filename)
                if finding:
                    findings.append(finding)
            
            # Log any errors
            if stderr.strip():
                self.logger.warning(f"Semgrep stderr: {stderr}")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing Semgrep JSON output: {e}")
            self.logger.debug(f"Raw output: {stdout}")
        
        return findings
    
    def _parse_finding(self, result: Dict, filename: str) -> Optional[Dict]:
        """
        Parse individual Semgrep finding.
        
        Args:
            result: Semgrep result object
            filename: Original filename
            
        Returns:
            Optional[Dict]: Parsed finding or None
        """
        try:
            # Extract basic information
            check_id = result.get('check_id', '')
            message = result.get('message', '')
            severity = result.get('severity', 'WARNING')
            confidence = result.get('confidence', 'MEDIUM')
            
            # Extract location
            start = result.get('start', {})
            line = start.get('line', 1)
            
            # Extract code snippet
            snippet = result.get('extra', {}).get('lines', '')
            if not snippet:
                snippet = result.get('extra', {}).get('message', '')
            
            # Generate finding ID
            finding_id = generate_finding_id(filename, line, check_id, snippet)
            
            # Extract CWE from check_id or message
            cwe_id = extract_cwe_from_message(message)
            if not cwe_id.startswith('CWE-'):
                cwe_id = extract_cwe_from_message(check_id)
            
            # Parse severity and confidence
            parsed_severity = parse_semgrep_severity(severity)
            parsed_confidence = parse_semgrep_confidence(confidence)
            
            finding = {
                'id': finding_id,
                'cwe_id': cwe_id,
                'title': message[:100] if message else check_id,
                'severity': parsed_severity,
                'status': 'ACTIVE',
                'line': line,
                'snippet': as_utf8(snippet),
                'file': filename,
                'tool': 'semgrep',
                'confidence': parsed_confidence,
                'suppression_reason': None,
                'context': {
                    'check_id': check_id,
                    'message': message,
                    'severity': severity,
                    'confidence': confidence
                }
            }
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Error parsing finding: {e}")
            return None
    
    def validate_ruleset(self, ruleset: str) -> bool:
        """
        Validate if a ruleset is available.
        
        Args:
            ruleset: Ruleset to validate
            
        Returns:
            bool: True if ruleset is valid
        """
        if not self.semgrep_available:
            return False
        
        try:
            result = subprocess.run(
                ['semgrep', '--list-rules', '--config', ruleset],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            return False


# Global Semgrep runner instance
_semgrep_runner = None


def get_semgrep_runner() -> SemgrepRunner:
    """Get the global Semgrep runner instance."""
    global _semgrep_runner
    
    if _semgrep_runner is None:
        _semgrep_runner = SemgrepRunner()
    
    return _semgrep_runner


def run_semgrep_scan(filename: str, code: str, ruleset: str = "p/security-audit") -> Tuple[List[Dict], bool, bool]:
    """
    Run Semgrep scan on code.
    
    Args:
        filename: Name of the file to scan
        code: Source code to analyze
        ruleset: Semgrep ruleset to use
        
    Returns:
        Tuple[List[Dict], bool, bool]: (findings, timeout, truncated)
    """
    runner = get_semgrep_runner()
    return runner.run_scan(filename, code, ruleset)


def get_semgrep_version() -> Optional[str]:
    """
    Get Semgrep version.
    
    Returns:
        Optional[str]: Semgrep version or None
    """
    runner = get_semgrep_runner()
    return runner.get_semgrep_version()


def is_semgrep_available() -> bool:
    """
    Check if Semgrep is available.
    
    Returns:
        bool: True if Semgrep is available
    """
    runner = get_semgrep_runner()
    return runner.semgrep_available
