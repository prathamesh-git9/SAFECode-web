"""False positive suppression system for SAFECode-Web backend."""

import re
from typing import List, Dict, Optional, Tuple
import logging

from .config import get_config
from .utils import as_utf8


class SuppressionRule:
    """Base class for suppression rules."""
    
    def __init__(self, name: str, description: str):
        """
        Initialize suppression rule.
        
        Args:
            name: Rule name
            description: Rule description
        """
        self.name = name
        self.description = description
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        """
        Check if finding matches this suppression rule.
        
        Args:
            finding: Finding dictionary
            code: Source code
            
        Returns:
            Tuple[bool, float, Optional[str]]: (matches, confidence, reason)
        """
        raise NotImplementedError


class PrintfLiteralFormatRule(SuppressionRule):
    """Suppress printf with literal format strings."""
    
    def __init__(self):
        super().__init__(
            "printf_literal_format",
            "Suppress printf with literal format strings"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') != 'CWE-134':
            return False, 0.0, None
        
        # Look for printf with literal format string
        line_num = finding.get('line', 0)
        snippet = finding.get('snippet', '')
        
        # Check if format string is literal (no %s with variable)
        if re.search(r'printf\s*\(\s*["\'][^"\']*["\']', snippet):
            # Check if it's a simple literal format
            if not re.search(r'%[^%]*[a-zA-Z]', snippet):
                return True, 0.95, "Literal format string in printf"
        
        return False, 0.0, None


class StrncpyBoundsPlusNulRule(SuppressionRule):
    """Suppress strncpy with proper bounds and null termination."""
    
    def __init__(self):
        super().__init__(
            "strncpy_bounds_plus_nul",
            "Suppress strncpy with proper bounds and null termination"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') not in ['CWE-120', 'CWE-121', 'CWE-122']:
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for strncpy with size-1 and explicit null termination
        if re.search(r'strncpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)', snippet):
            # Check for explicit null termination on next line
            lines = code.split('\n')
            line_num = finding.get('line', 0) - 1  # Convert to 0-based
            
            if line_num + 1 < len(lines):
                next_line = lines[line_num + 1].strip()
                if re.search(r'\[.*\]\s*=\s*[\'"]\\0[\'"]', next_line):
                    return True, 0.95, "strncpy with explicit null termination"
        
        return False, 0.0, None


class StrncatSpaceGuardRule(SuppressionRule):
    """Suppress strncat with space guard."""
    
    def __init__(self):
        super().__init__(
            "strncat_space_guard",
            "Suppress strncat with space guard"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') not in ['CWE-120', 'CWE-121', 'CWE-122']:
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for strncat with remaining space calculation
        if re.search(r'strncat\s*\([^,]+,\s*[^,]+,\s*[^)]+\)', snippet):
            # Check for space guard pattern
            if re.search(r'sizeof\s*\([^)]+\)\s*-\s*strlen\s*\([^)]+\)\s*-\s*1', snippet):
                return True, 0.95, "strncat with space guard"
        
        return False, 0.0, None


class ExeclNoShellRule(SuppressionRule):
    """Suppress execl without shell."""
    
    def __init__(self):
        super().__init__(
            "execl_no_shell",
            "Suppress execl without shell"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') not in ['CWE-78', 'CWE-88']:
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for execl without shell
        if re.search(r'execl\s*\([^,]+,\s*[^,]+,\s*NULL\s*\)', snippet):
            return True, 0.95, "execl without shell"
        
        return False, 0.0, None


class OverflowGuardRule(SuppressionRule):
    """Suppress integer overflow with guards."""
    
    def __init__(self):
        super().__init__(
            "overflow_guard",
            "Suppress integer overflow with guards"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') != 'CWE-190':
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for overflow guards
        guard_patterns = [
            r'if\s*\([^)]*>\s*SIZE_MAX\s*-\s*[^)]*\)',
            r'if\s*\([^)]*!=\s*0\s*&&\s*[^)]*>\s*SIZE_MAX\s*/\s*[^)]*\)',
            r'if\s*\([^)]*<\s*[^)]*\)',  # Simple bounds check
        ]
        
        for pattern in guard_patterns:
            if re.search(pattern, snippet):
                return True, 0.95, "Integer overflow with guard"
        
        return False, 0.0, None


class FreeThenNullRule(SuppressionRule):
    """Suppress double free with null assignment."""
    
    def __init__(self):
        super().__init__(
            "free_then_null",
            "Suppress double free with null assignment"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') not in ['CWE-415', 'CWE-416']:
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for free followed by null assignment
        if re.search(r'free\s*\([^)]+\)', snippet):
            lines = code.split('\n')
            line_num = finding.get('line', 0) - 1
            
            # Check next few lines for null assignment
            for i in range(line_num + 1, min(line_num + 3, len(lines))):
                line = lines[i].strip()
                if re.search(r'=\s*NULL', line):
                    return True, 0.95, "free followed by null assignment"
        
        return False, 0.0, None


class NullGuardedUseRule(SuppressionRule):
    """Suppress null pointer dereference with null check."""
    
    def __init__(self):
        super().__init__(
            "null_guarded_use",
            "Suppress null pointer dereference with null check"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        if finding.get('cwe_id') != 'CWE-476':
            return False, 0.0, None
        
        snippet = finding.get('snippet', '')
        
        # Look for null checks before dereference
        null_check_patterns = [
            r'if\s*\([^)]*!=\s*NULL\s*\)',
            r'if\s*\([^)]*\)',  # Any if statement before dereference
        ]
        
        for pattern in null_check_patterns:
            if re.search(pattern, snippet):
                return True, 0.90, "Null pointer with null check"
        
        return False, 0.0, None


class ContextSafeRule(SuppressionRule):
    """Suppress findings based on context analysis."""
    
    def __init__(self):
        super().__init__(
            "context_safe",
            "Suppress findings based on context analysis"
        )
    
    def matches(self, finding: Dict, code: str) -> Tuple[bool, float, Optional[str]]:
        snippet = finding.get('snippet', '')
        cwe = finding.get('cwe_id', '')
        
        # Context-specific suppressions
        if cwe == 'CWE-134' and 'printf("%s",' in snippet:
            return True, 0.95, "Safe printf with %s format"
        
        if cwe in ['CWE-120', 'CWE-121', 'CWE-122']:
            # Check for safe string operations
            if 'strlcpy(' in snippet or 'strlcat(' in snippet:
                return True, 0.95, "Safe string operation (strlcpy/strlcat)"
            
            if 'snprintf(' in snippet and 'sizeof(' in snippet:
                return True, 0.95, "Safe snprintf with sizeof"
        
        return False, 0.0, None


class SuppressionEngine:
    """Engine for applying false positive suppressions."""
    
    def __init__(self):
        """Initialize suppression engine with rules."""
        self.rules = [
            PrintfLiteralFormatRule(),
            StrncpyBoundsPlusNulRule(),
            StrncatSpaceGuardRule(),
            ExeclNoShellRule(),
            OverflowGuardRule(),
            FreeThenNullRule(),
            NullGuardedUseRule(),
            ContextSafeRule(),
        ]
        
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
    
    def apply_false_positive_suppression(self, findings: List[Dict], code: str) -> List[Dict]:
        """
        Apply false positive suppression to findings.
        
        Args:
            findings: List of findings
            code: Source code
            
        Returns:
            List[Dict]: Findings with suppression applied
        """
        suppressed_count = 0
        
        for finding in findings:
            # Check safety gates first
            if self._should_never_suppress(finding):
                continue
            
            # Apply suppression rules
            for rule in self.rules:
                matches, confidence, reason = rule.matches(finding, code)
                
                if matches and self._check_safety_gates(finding, confidence):
                    finding['status'] = 'SUPPRESSED'
                    finding['suppression_reason'] = f"{rule.name}: {reason}"
                    finding['confidence'] = self._adjust_confidence(confidence)
                    suppressed_count += 1
                    break
        
        self.logger.info(f"Suppressed {suppressed_count} findings out of {len(findings)}")
        return findings
    
    def _should_never_suppress(self, finding: Dict) -> bool:
        """Check if finding should never be suppressed."""
        snippet = finding.get('snippet', '')
        
        # Check for never-suppress functions
        for func in self.config.NEVER_SUPPRESS_FUNCS:
            if func in snippet:
                return True
        
        return False
    
    def _check_safety_gates(self, finding: Dict, confidence: float) -> bool:
        """Check safety gates for suppression."""
        cwe = finding.get('cwe_id', '')
        
        # Check strict minimum confidence for specific CWEs
        strict_min = self.config.STRICT_MIN.get(cwe, 0.0)
        if confidence < strict_min:
            return False
        
        return True
    
    def _adjust_confidence(self, confidence: float) -> str:
        """Convert confidence float to string."""
        if confidence >= 0.95:
            return 'high'
        elif confidence >= 0.8:
            return 'medium'
        else:
            return 'low'


# Global suppression engine instance
_suppression_engine = None


def get_suppression_engine() -> SuppressionEngine:
    """Get the global suppression engine instance."""
    global _suppression_engine
    
    if _suppression_engine is None:
        _suppression_engine = SuppressionEngine()
    
    return _suppression_engine


def apply_suppression(findings: List[Dict], code: str) -> List[Dict]:
    """
    Apply false positive suppression to findings.
    
    Args:
        findings: List of findings
        code: Source code
        
    Returns:
        List[Dict]: Findings with suppression applied
    """
    engine = get_suppression_engine()
    return engine.apply_false_positive_suppression(findings, code)
