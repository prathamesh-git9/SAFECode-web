"""False-positive suppression system for SAFECode-Web."""
import re
import logging
from typing import List, Dict, Tuple, Optional
from abc import ABC, abstractmethod

from .config import get_config

logger = logging.getLogger(__name__)

class SuppressionRule(ABC):
    """Base class for suppression rules."""
    
    @abstractmethod
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        """Check if rule matches the finding.
        
        Returns:
            Tuple of (matches, reason, confidence_boost)
        """
        pass

class PrintfLiteralFormatRule(SuppressionRule):
    """R1: printf_family_literal_format - Safe literal format strings."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-134":
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function not in ["printf", "fprintf", "dprintf", "snprintf", "vsnprintf", "vfprintf", "vprintf"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for literal format string without %n
        if self._has_literal_format(line_content) and "%n" not in line_content:
            return True, "printf_literal_format", 0.95
        return False, "", 0.0

class SnprintfLiteralFormatRule(SuppressionRule):
    """R2: snprintf_literal_format - Safe snprintf with explicit size."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-134":
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "snprintf":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for snprintf with explicit size and literal format
        if self._has_literal_format(line_content) and self._has_explicit_size(line_content):
            return True, "snprintf_literal_format", 0.95
        return False, "", 0.0

class FormatStringSafeForwardRule(SuppressionRule):
    """R3: format_string_forwarding_safe - Safe format string forwarding."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-134":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for safe forwarding patterns
        safe_patterns = [
            r'fprintf\s*\([^,]+,\s*"%s"',  # fprintf(fd, "%s", var)
            r'printf\s*\([^,]*"%.\*s"',    # printf("%.*s", width, var)
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, line_content):
                return True, "format_string_safe_forward", 0.90
        return False, "", 0.0

class ExeclNoShellRule(SuppressionRule):
    """R4: execl_no_shell - Safe exec without shell."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-78":
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if not function.startswith("exec"):
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for constant path and -- stop option
        if self._has_constant_path(line_content) and "--" in line_content:
            return True, "execl_no_shell", 0.95
        return False, "", 0.0

class ExecArgAllowlistRule(SuppressionRule):
    """R5: exec_arg_allowlist_token - Safe argument validation."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-78":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for allowlist validation
        allowlist_patterns = [
            r'is_safe_token\s*\(',
            r'validate_arg\s*\(',
            r'[A-Za-z0-9._/-]+\s*&&\s*!.*\.\.',
        ]
        
        for pattern in allowlist_patterns:
            if re.search(pattern, "\n".join(prev_lines)):
                return True, "exec_arg_allowlist", 0.90
        return False, "", 0.0

class ExecConstArgvRule(SuppressionRule):
    """R6: exec_const_argv - Constant argument arrays."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-78":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for string literal arrays
        if re.search(r'\{[^}]*"[^"]*"[^}]*\}', line_content):
            return True, "exec_const_argv", 0.90
        return False, "", 0.0

class StrncpyBoundsPlusNulRule(SuppressionRule):
    """R7: strncpy_bounds_plus_nul - Safe strncpy with null termination."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-120", "CWE-121", "CWE-122"]:
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "strncpy":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        next_lines = self._get_next_lines(code, line, 3)
        
        # Check for bounds checking and null termination
        bounds_pattern = r'sizeof\s*\([^)]+\)\s*-\s*1'
        null_pattern = r'\[[^\]]+\]\s*=\s*[\'"]\\0[\'"]'
        
        if (re.search(bounds_pattern, self._get_line(code, line)) and 
            any(re.search(null_pattern, line) for line in next_lines)):
            return True, "strncpy_bounds_plus_nul", 0.95
        return False, "", 0.0

class StrncatSpaceGuardRule(SuppressionRule):
    """R8: strncat_space_guard - Safe strncat with space checking."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-120", "CWE-121", "CWE-122"]:
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "strncat":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 3)
        
        # Check for space calculation
        space_patterns = [
            r'room\s*=\s*cap\s*-\s*1\s*-\s*strlen',
            r'sizeof\s*\([^)]+\)\s*-\s*strlen',
        ]
        
        for pattern in space_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "strncat_space_guard", 0.90
        return False, "", 0.0

class ScanfWidthSpecifierRule(SuppressionRule):
    """R9: scanf_width_specifier - Safe scanf with width specifiers."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-120":
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function not in ["scanf", "fscanf", "sscanf"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for width specifiers
        if re.search(r'%\d+s', line_content):
            return True, "scanf_width_guard", 0.90
        return False, "", 0.0

class BoundsCheckedIndexRule(SuppressionRule):
    """R10: bounds_checked_index - Safe array indexing."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-120", "CWE-787"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for bounds checking
        bounds_patterns = [
            r'for\s*\([^)]*i\s*<\s*sizeof\s*\([^)]+\)\s*/\s*sizeof',
            r'if\s*\([^)]*i\s*<\s*[A-Z_][A-Z0-9_]*[^)]*\)',
        ]
        
        for pattern in bounds_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "index_bounds_guard", 0.90
        return False, "", 0.0

class AllocAddOverflowGuardRule(SuppressionRule):
    """R11: alloc_add_overflow_guard - Safe addition with overflow check."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-190", "CWE-191"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for overflow guards
        guard_patterns = [
            r'if\s*\([^)]*>\s*SIZE_MAX\s*-\s*[^)]*\)',
            r'if\s*\([^)]*a\s*>\s*SIZE_MAX\s*-\s*b[^)]*\)',
        ]
        
        for pattern in guard_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "overflow_guard", 0.95
        return False, "", 0.0

class MulOverflowGuardRule(SuppressionRule):
    """R12: mul_overflow_guard - Safe multiplication with overflow check."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-190", "CWE-191"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for multiplication overflow guards
        guard_pattern = r'if\s*\([^)]*!=\s*0\s*&&\s*[^)]*>\s*SIZE_MAX\s*/\s*[^)]*\)'
        
        if any(re.search(guard_pattern, line) for line in prev_lines):
            return True, "overflow_guard_mul", 0.95
        return False, "", 0.0

class SignedUnderflowGuardRule(SuppressionRule):
    """R13: signed_underflow_guard - Safe signed arithmetic."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-190", "CWE-191"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for underflow guards
        guard_pattern = r'if\s*\([^)]*<\s*MIN\s*\+\s*[^)]*\)'
        
        if any(re.search(guard_pattern, line) for line in prev_lines):
            return True, "underflow_guard", 0.90
        return False, "", 0.0

class FreeThenNullRule(SuppressionRule):
    """R14: free_then_null - Safe free with null assignment."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-401", "CWE-415", "CWE-416"]:
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "free":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        next_lines = self._get_next_lines(code, line, 3)
        
        # Check for null assignment after free
        null_pattern = r'=\s*NULL'
        
        if any(re.search(null_pattern, line) for line in next_lines):
            return True, "free_then_null", 0.90
        return False, "", 0.0

class NullGuardedUseRule(SuppressionRule):
    """R15: null_guarded_use - Safe null pointer usage."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-476", "CWE-415", "CWE-416"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 3)
        
        # Check for null guards
        guard_patterns = [
            r'if\s*\([^)]*!\s*[^)]*\)',
            r'if\s*\([^)]*[^)]*\)\s*\{[^}]*\*[^}]*\}',
        ]
        
        for pattern in guard_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "null_guarded_use", 0.90
        return False, "", 0.0

class NoPostFreeUseRule(SuppressionRule):
    """R16: no_post_free_use - No use after free."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-415", "CWE-416"]:
            return False, "", 0.0
            
        line = finding.get("line", 0)
        next_lines = self._get_next_lines(code, line, 10)
        
        # Check that pointer is not used after free
        free_line = self._get_line(code, line)
        pointer_match = re.search(r'free\s*\(([^)]+)\)', free_line)
        if not pointer_match:
            return False, "", 0.0
            
        pointer = pointer_match.group(1).strip()
        
        # Look for uses of the pointer after free
        for next_line in next_lines:
            if re.search(rf'\*{re.escape(pointer)}', next_line) or re.search(rf'{re.escape(pointer)}\[', next_line):
                return False, "", 0.0
        
        return True, "no_post_free_use", 0.85

class LeakHandledOnErrorRule(SuppressionRule):
    """R17: leak_handled_on_error - Memory leak handled on error paths."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-401":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        next_lines = self._get_next_lines(code, line, 10)
        
        # Check for error handling with cleanup
        error_patterns = [
            r'if\s*\([^)]*error[^)]*\)\s*\{[^}]*free[^}]*\}',
            r'if\s*\([^)]*NULL[^)]*\)\s*\{[^}]*free[^}]*\}',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, "\n".join(next_lines)):
                return True, "leak_guard", 0.90
        return False, "", 0.0

class RelpathAllowlistRule(SuppressionRule):
    """R18: relpath_allowlist - Safe relative path validation."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-22":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 5)
        
        # Check for path validation
        validation_patterns = [
            r'is_safe_relpath\s*\(',
            r'validate_path\s*\(',
            r'!.*\.\.',
        ]
        
        for pattern in validation_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "relpath_allowlist", 0.90
        return False, "", 0.0

class OpenExclusiveRule(SuppressionRule):
    """R19: open_exclusive - Safe file creation with O_EXCL."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") not in ["CWE-22", "CWE-367"]:
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "open":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for O_CREAT|O_EXCL flags
        if re.search(r'O_CREAT\s*\|\s*O_EXCL', line_content):
            return True, "toctou_o_excl", 0.95
        return False, "", 0.0

class MkstempOkRule(SuppressionRule):
    """R20: mkstemp_ok - Safe temporary file creation."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-377":
            return False, "", 0.0
            
        function = finding.get("context", {}).get("function", "")
        if function != "mkstemp":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        next_lines = self._get_next_lines(code, line, 10)
        
        # Check for proper mkstemp usage
        if any("close" in line for line in next_lines):
            return True, "mkstemp_safe", 0.95
        return False, "", 0.0

class SizeofFixedBufferRule(SuppressionRule):
    """R21: sizeof_fixed_buffer - Safe sizeof on arrays."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-467":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for sizeof on array variables
        if re.search(r'sizeof\s*\([A-Za-z_][A-Za-z0-9_]*\)', line_content):
            return True, "sizeof_fixed_buffer", 0.90
        return False, "", 0.0

class SizeofDerefPointerRule(SuppressionRule):
    """R22: sizeof_deref_pointer - Safe sizeof on dereferenced pointers."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-467":
            return False, "", 0.0
            
        line = finding.get("line", 0)
        line_content = self._get_line(code, line)
        
        # Check for sizeof(*ptr) pattern
        if re.search(r'sizeof\s*\(\*[^)]+\)', line_content):
            return True, "sizeof_deref_pointer", 0.90
        return False, "", 0.0

class CryptographicSourceUsedRule(SuppressionRule):
    """R23: cryptographic_source_used - Cryptographic RNG present."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        if finding.get("cwe_id") != "CWE-330":
            return False, "", 0.0
            
        # Check if cryptographic RNG is used elsewhere
        crypto_patterns = [
            r'getrandom\s*\(',
            r'arc4random\s*\(',
            r'/dev/urandom',
            r'RAND_bytes\s*\(',
        ]
        
        for pattern in crypto_patterns:
            if re.search(pattern, code):
                return True, "crypto_rng_present", 0.85
        return False, "", 0.0

class ContextSafeRule(SuppressionRule):
    """R24: context_safe - Safe context markers."""
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, str, float]:
        line = finding.get("line", 0)
        prev_lines = self._get_prev_lines(code, line, 3)
        
        # Check for safe context markers
        safe_patterns = [
            r'/\*\s*safe\s*\*/',
            r'//\s*safe',
            r'/\*\s*test\s*\*/',
            r'//\s*test',
        ]
        
        for pattern in safe_patterns:
            if any(re.search(pattern, line) for line in prev_lines):
                return True, "context_safe", 0.80
        return False, "", 0.0

class SuppressionEngine:
    """Engine for applying false-positive suppression rules."""
    
    def __init__(self):
        self.config = get_config()
        self.rules = [
            PrintfLiteralFormatRule(),
            SnprintfLiteralFormatRule(),
            FormatStringSafeForwardRule(),
            ExeclNoShellRule(),
            ExecArgAllowlistRule(),
            ExecConstArgvRule(),
            StrncpyBoundsPlusNulRule(),
            StrncatSpaceGuardRule(),
            ScanfWidthSpecifierRule(),
            BoundsCheckedIndexRule(),
            AllocAddOverflowGuardRule(),
            MulOverflowGuardRule(),
            SignedUnderflowGuardRule(),
            FreeThenNullRule(),
            NullGuardedUseRule(),
            NoPostFreeUseRule(),
            LeakHandledOnErrorRule(),
            RelpathAllowlistRule(),
            OpenExclusiveRule(),
            MkstempOkRule(),
            SizeofFixedBufferRule(),
            SizeofDerefPointerRule(),
            CryptographicSourceUsedRule(),
            ContextSafeRule(),
        ]
    
    def apply_suppression(self, findings: List[Dict], code: str) -> List[Dict]:
        """Apply false-positive suppression to findings."""
        config = get_config()
        suppressed_count = 0
        
        for finding in findings:
            # Check never-suppress functions
            function = finding.get("context", {}).get("function", "")
            if function in config.never_suppress_funcs:
                continue
            
            # Check strict thresholds
            cwe_id = finding.get("cwe_id", "")
            min_threshold = config.safe_strict_min_thresholds.get(cwe_id, 0.90)
            confidence = finding.get("confidence", 0.80)
            
            if confidence < min_threshold:
                continue
            
            # Apply rules in order
            for rule in self.rules:
                matches, reason, confidence_boost = rule.matches(finding, code)
                if matches:
                    finding["status"] = "SUPPRESSED"
                    finding["suppression_reason"] = reason
                    finding["suppression_confidence"] = confidence_boost
                    suppressed_count += 1
                    break
        
        logger.info(f"Suppressed {suppressed_count} findings out of {len(findings)}")
        return findings
    
    def _get_line(self, code: str, line_num: int) -> str:
        """Get specific line from code."""
        lines = code.split('\n')
        if 0 <= line_num - 1 < len(lines):
            return lines[line_num - 1]
        return ""
    
    def _get_prev_lines(self, code: str, line_num: int, count: int) -> List[str]:
        """Get previous lines from code."""
        lines = code.split('\n')
        start = max(0, line_num - count - 1)
        end = line_num - 1
        return lines[start:end]
    
    def _get_next_lines(self, code: str, line_num: int, count: int) -> List[str]:
        """Get next lines from code."""
        lines = code.split('\n')
        start = line_num
        end = min(len(lines), line_num + count)
        return lines[start:end]

# Global suppression engine instance
suppression_engine = SuppressionEngine()

def apply_false_positive_suppression(findings: List[Dict], code: str) -> List[Dict]:
    """Apply false-positive suppression to findings."""
    return suppression_engine.apply_suppression(findings, code)
