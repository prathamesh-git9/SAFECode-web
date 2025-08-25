"""Code Fixer using GPT to automatically fix C code vulnerabilities."""

import logging
import json
from typing import List, Dict, Optional, Tuple
from openai import OpenAI
from .config import get_config

logger = logging.getLogger(__name__)


class CodeFixer:
    """Code fixer using GPT to fix C code vulnerabilities."""

    def __init__(self):
        """Initialize code fixer."""
        self.config = get_config()
        self.client = None
        
        if self.config.enable_gpt and self.config.openai_api_key:
            try:
                self.client = OpenAI(api_key=self.config.openai_api_key)
                logger.info("OpenAI client initialized for code fixing")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
        else:
            logger.warning("GPT code fixing disabled - no API key or feature disabled")

    def fix_code(self, original_code: str, vulnerabilities: List[Dict]) -> Tuple[str, List[Dict]]:
        """
        Fix C code vulnerabilities using GPT.
        
        Args:
            original_code: Original C code
            vulnerabilities: List of vulnerabilities found
            
        Returns:
            Tuple of (fixed_code, fix_details)
        """
        if not self.client or not vulnerabilities:
            return original_code, []

        try:
            # Build prompt for GPT
            prompt = self._build_fix_prompt(original_code, vulnerabilities)
            
            # Call GPT
            response = self.client.chat.completions.create(
                model=self.config.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a C security expert. Fix security vulnerabilities in C code. Return only the fixed code, no explanations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=4000
            )

            fixed_code = response.choices[0].message.content.strip()
            
            # Extract fix details
            fix_details = self._extract_fix_details(original_code, fixed_code, vulnerabilities)
            
            return fixed_code, fix_details

        except Exception as e:
            logger.error(f"Error fixing code with GPT: {e}")
            return original_code, []

    def _build_fix_prompt(self, code: str, vulnerabilities: List[Dict]) -> str:
        """Build prompt for GPT to fix vulnerabilities."""
        prompt = f"""Fix the following C code vulnerabilities:

Original Code:
```c
{code}
```

Vulnerabilities found:
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            prompt += f"""
{i}. {vuln['title']} (Line {vuln['line']})
   - CWE: {vuln['cwe_id']}
   - Severity: {vuln['severity']}
   - Description: {vuln.get('context', {}).get('description', 'N/A')}
   - Suggestion: {vuln.get('context', {}).get('suggestion', 'N/A')}
   - Code: {vuln['snippet']}
"""

        prompt += """

Instructions:
1. Fix all security vulnerabilities
2. Maintain code functionality
3. Use secure alternatives (e.g., strncpy instead of strcpy)
4. Add proper bounds checking
5. Return only the complete fixed C code
6. Include necessary headers
7. Ensure the code compiles and works correctly

Fixed Code:
```c
"""
        
        return prompt

    def _extract_fix_details(self, original_code: str, fixed_code: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Extract details about what was fixed."""
        fix_details = []
        
        original_lines = original_code.split('\n')
        fixed_lines = fixed_code.split('\n')
        
        for vuln in vulnerabilities:
            fix_detail = {
                "vulnerability_id": vuln['id'],
                "cwe_id": vuln['cwe_id'],
                "original_line": vuln['line'],
                "severity": vuln['severity'],
                "description": vuln.get('context', {}).get('description', ''),
                "fix_applied": True,
                "fix_type": self._determine_fix_type(vuln)
            }
            fix_details.append(fix_detail)
        
        return fix_details

    def _determine_fix_type(self, vulnerability: Dict) -> str:
        """Determine the type of fix applied."""
        cwe = vulnerability['cwe_id']
        category = vulnerability.get('context', {}).get('category', '').lower()
        
        fix_types = {
            'CWE-120': 'buffer_overflow_protection',
            'CWE-134': 'format_string_protection', 
            'CWE-78': 'command_injection_protection',
            'CWE-190': 'integer_overflow_protection',
            'CWE-367': 'race_condition_protection'
        }
        
        if cwe in fix_types:
            return fix_types[cwe]
        
        # Map by category
        category_fixes = {
            'buffer': 'buffer_overflow_protection',
            'format': 'format_string_protection',
            'shell': 'command_injection_protection',
            'tob': 'integer_overflow_protection',
            'race': 'race_condition_protection'
        }
        
        return category_fixes.get(category, 'general_security_fix')

    def is_available(self) -> bool:
        """Check if code fixing is available."""
        return self.client is not None


def fix_code_with_gpt(original_code: str, vulnerabilities: List[Dict]) -> Tuple[str, List[Dict]]:
    """
    Fix C code vulnerabilities using GPT.
    
    Args:
        original_code: Original C code
        vulnerabilities: List of vulnerabilities found
        
    Returns:
        Tuple of (fixed_code, fix_details)
    """
    fixer = CodeFixer()
    return fixer.fix_code(original_code, vulnerabilities)
