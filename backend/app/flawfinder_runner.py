"""Flawfinder runner for C/C++ static analysis."""
import subprocess
import tempfile
import os
import json
import logging
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from .config import get_config
from .utils import truncate_snippet, as_utf8

logger = logging.getLogger(__name__)

@dataclass
class FlawfinderFinding:
    """Raw finding from Flawfinder."""
    file: str
    line: int
    column: int
    function: str
    message: str
    risk_level: int
    rule: str
    context: str = ""

class FlawfinderRunner:
    """Runner for Flawfinder static analysis tool."""
    
    def __init__(self):
        self.config = get_config()
        self.tool_name = self.config.flawfinder_path
        
        # CWE mapping for Flawfinder rules
        self.cwe_mapping = {
            "strcpy": "CWE-120",
            "strcat": "CWE-120", 
            "gets": "CWE-120",
            "sprintf": "CWE-134",
            "vsprintf": "CWE-134",
            "scanf": "CWE-120",
            "sscanf": "CWE-120",
            "system": "CWE-78",
            "popen": "CWE-78",
            "execl": "CWE-78",
            "execle": "CWE-78",
            "execlp": "CWE-78",
            "execv": "CWE-78",
            "execve": "CWE-78",
            "execvp": "CWE-78",
            "access": "CWE-367",
            "tmpnam": "CWE-377",
            "mktemp": "CWE-377",
            "rand": "CWE-330",
            "srand": "CWE-330",
            "memcpy": "CWE-787",
            "memmove": "CWE-787",
            "strncpy": "CWE-120",
            "strncat": "CWE-122",
            "fgets": "CWE-120",
            "fscanf": "CWE-120",
            "printf": "CWE-134",
            "fprintf": "CWE-134",
            "snprintf": "CWE-134",
            "vsnprintf": "CWE-134",
            "strlen": "CWE-476",
            "open": "CWE-22",
            "fopen": "CWE-22",
            "readlink": "CWE-22",
            "malloc": "CWE-190",
            "realloc": "CWE-190",
            "free": "CWE-415"
        }
        
        # Severity mapping
        self.severity_map = {
            5: "CRITICAL",
            4: "HIGH", 
            3: "MEDIUM",
            2: "MEDIUM",
            1: "LOW",
            0: "LOW"
        }
        
        # High-risk functions that get confidence boost
        self.high_risk_funcs = {
            "strcpy", "strcat", "system", "popen", "tmpnam", 
            "execl", "execle", "execlp", "execv", "execve", "execvp"
        }

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

    def run_scan(self, code: str, filename: str = "code.c") -> Tuple[List[Dict], bool]:
        """Run Flawfinder scan and return findings."""
        if not self.check_availability():
            return [], False
            
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.c',
                delete=False,
                encoding='utf-8'
            ) as temp_file:
                temp_file.write(as_utf8(code))
                temp_file_path = temp_file.name
            
            # Try SARIF output first, fallback to text
            findings, success = self._run_sarif_scan(temp_file_path)
            if not success:
                findings, success = self._run_text_scan(temp_file_path)
            
            # Apply limits and truncation
            if len(findings) > self.config.flawfinder_max_findings:
                logger.warning(f"Truncating findings from {len(findings)} to {self.config.flawfinder_max_findings}")
                findings = findings[:self.config.flawfinder_max_findings]
            
            os.unlink(temp_file_path)
            return findings, success
            
        except Exception as e:
            logger.error(f"Error running Flawfinder: {e}")
            return [], False

    def _run_sarif_scan(self, file_path: str) -> Tuple[List[Dict], bool]:
        """Run Flawfinder with SARIF output."""
        try:
            cmd = [
                self.tool_name,
                "--quiet",
                "--singleline", 
                "--dataonly",
                "--columns",
                "--sarif",
                file_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.flawfinder_timeout
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_sarif_output(result.stdout, file_path)
            else:
                logger.debug("SARIF output not available, falling back to text")
                return [], False
                
        except subprocess.TimeoutExpired:
            logger.error("Flawfinder SARIF scan timed out")
            return [], False
        except Exception as e:
            logger.error(f"Error in SARIF scan: {e}")
            return [], False

    def _run_text_scan(self, file_path: str) -> Tuple[List[Dict], bool]:
        """Run Flawfinder with text output."""
        try:
            cmd = [
                self.tool_name,
                "--quiet",
                "--singleline",
                "--dataonly",
                file_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.flawfinder_timeout
            )
            
            if result.returncode == 0:
                return self._parse_text_output(result.stdout, file_path)
            else:
                logger.error(f"Flawfinder text scan failed: {result.stderr}")
                return [], False
                
        except subprocess.TimeoutExpired:
            logger.error("Flawfinder text scan timed out")
            return [], False
        except Exception as e:
            logger.error(f"Error in text scan: {e}")
            return [], False

    def _parse_sarif_output(self, output: str, file_path: str) -> Tuple[List[Dict], bool]:
        """Parse SARIF output from Flawfinder."""
        try:
            sarif_data = json.loads(output)
            findings = []
            
            for run in sarif_data.get("runs", []):
                for result in run.get("results", []):
                    finding = self._extract_finding_from_sarif(result, file_path)
                    if finding:
                        findings.append(finding)
            
            return findings, True
            
        except json.JSONDecodeError:
            logger.error("Failed to parse SARIF JSON output")
            return [], False
        except Exception as e:
            logger.error(f"Error parsing SARIF: {e}")
            return [], False

    def _parse_text_output(self, output: str, file_path: str) -> Tuple[List[Dict], bool]:
        """Parse text output from Flawfinder."""
        findings = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            finding = self._extract_finding_from_text(line, file_path)
            if finding:
                findings.append(finding)
        
        return findings, True

    def _extract_finding_from_sarif(self, result: Dict, file_path: str) -> Optional[Dict]:
        """Extract finding from SARIF result."""
        try:
            location = result.get("locations", [{}])[0]
            physical_location = location.get("physicalLocation", {})
            
            line = physical_location.get("startLine", 1)
            column = physical_location.get("startColumn", 1)
            
            message = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId", "")
            
            # Extract risk level from rule ID or message
            risk_level = self._extract_risk_level(rule_id, message)
            
            # Get function name if available
            function = self._extract_function_name(message)
            
            # Get CWE ID
            cwe_id = self._get_cwe_id(rule_id, function)
            
            # Calculate confidence
            confidence = self._calculate_confidence(function, risk_level)
            
            # Get snippet
            snippet = self._get_snippet(file_path, line)
            
            return {
                "id": f"flawfinder_{line}_{column}_{hash(rule_id) % 10000}",
                "cwe_id": cwe_id,
                "title": f"{rule_id} vulnerability",
                "severity": self.severity_map.get(risk_level, "MEDIUM"),
                "status": "ACTIVE",
                "line": line,
                "column": column,
                "snippet": snippet,
                "file": os.path.basename(file_path),
                "tool": "flawfinder",
                "confidence": confidence,
                "suppression_reason": None,
                "context": {
                    "function": function,
                    "rule": rule_id,
                    "message": message,
                    "risk_level": risk_level
                }
            }
            
        except Exception as e:
            logger.error(f"Error extracting SARIF finding: {e}")
            return None

    def _extract_finding_from_text(self, line: str, file_path: str) -> Optional[Dict]:
        """Extract finding from text output line."""
        try:
            # Parse text format: file:line:function:risk:message
            parts = line.split(':', 4)
            if len(parts) < 4:
                return None
                
            filename, line_str, function, risk_str, *message_parts = parts
            line_num = int(line_str)
            risk_level = int(risk_str)
            message = ':'.join(message_parts) if message_parts else ""
            
            # Extract rule from message or function
            rule = self._extract_rule_from_message(message, function)
            
            # Get CWE ID
            cwe_id = self._get_cwe_id(rule, function)
            
            # Calculate confidence
            confidence = self._calculate_confidence(function, risk_level)
            
            # Get snippet
            snippet = self._get_snippet(file_path, line_num)
            
            return {
                "id": f"flawfinder_{line_num}_{hash(rule) % 10000}",
                "cwe_id": cwe_id,
                "title": f"{rule} vulnerability",
                "severity": self.severity_map.get(risk_level, "MEDIUM"),
                "status": "ACTIVE", 
                "line": line_num,
                "column": 1,  # Default column
                "snippet": snippet,
                "file": os.path.basename(file_path),
                "tool": "flawfinder",
                "confidence": confidence,
                "suppression_reason": None,
                "context": {
                    "function": function,
                    "rule": rule,
                    "message": message,
                    "risk_level": risk_level
                }
            }
            
        except Exception as e:
            logger.error(f"Error extracting text finding: {e}")
            return None

    def _extract_risk_level(self, rule_id: str, message: str) -> int:
        """Extract risk level from rule ID or message."""
        # Try to extract from rule ID first
        if rule_id and rule_id.isdigit():
            return int(rule_id)
        
        # Look for risk level in message
        risk_match = re.search(r'risk level (\d+)', message.lower())
        if risk_match:
            return int(risk_match.group(1))
        
        # Default based on function type
        if any(func in message.lower() for func in ["strcpy", "strcat", "system"]):
            return 5
        elif any(func in message.lower() for func in ["sprintf", "scanf"]):
            return 4
        else:
            return 3

    def _extract_function_name(self, message: str) -> str:
        """Extract function name from message."""
        # Look for function call pattern
        func_match = re.search(r'(\w+)\s*\(', message)
        if func_match:
            return func_match.group(1)
        return "unknown"

    def _extract_rule_from_message(self, message: str, function: str) -> str:
        """Extract rule name from message."""
        # Try to find function name in message
        if function and function != "unknown":
            return function
        
        # Look for common patterns
        for func in self.cwe_mapping.keys():
            if func in message.lower():
                return func
        
        return "unknown_rule"

    def _get_cwe_id(self, rule: str, function: str) -> str:
        """Get CWE ID for rule or function."""
        # Try rule first
        if rule in self.cwe_mapping:
            return self.cwe_mapping[rule]
        
        # Try function name
        if function in self.cwe_mapping:
            return self.cwe_mapping[function]
        
        # Default to general weakness
        return "CWE-20"

    def _calculate_confidence(self, function: str, risk_level: int) -> float:
        """Calculate confidence level for finding."""
        base_confidence = 0.80
        
        # Boost for high-risk functions
        if function in self.high_risk_funcs:
            base_confidence = 0.90
        
        # Boost for higher risk levels
        if risk_level >= 4:
            base_confidence += 0.05
        
        return min(base_confidence, 0.95)

    def _get_snippet(self, file_path: str, line_num: int) -> str:
        """Get code snippet around the finding line."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start_line = max(0, line_num - 2)
            end_line = min(len(lines), line_num + 1)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                line_content = lines[i].rstrip() if i < len(lines) else ""
                line_number = i + 1
                marker = ">>> " if line_number == line_num else "    "
                snippet_lines.append(f"{marker}{line_number:3d}: {line_content}")
            
            snippet = "\n".join(snippet_lines)
            return truncate_snippet(snippet, self.config.safe_max_snippet_chars)
            
        except Exception as e:
            logger.error(f"Error getting snippet: {e}")
            return f"Line {line_num}: Unable to extract snippet"

def analyze(filename: str, code: str) -> Tuple[List[Dict], bool]:
    """Analyze code using Flawfinder."""
    runner = FlawfinderRunner()
    return runner.run_scan(code, filename)
