"""AI integration module for SAFECode-Web backend."""

import time
import logging
from typing import List, Dict, Optional
import openai

from .config import get_config
from .utils import as_utf8


class AISuppressionEngine:
    """AI-powered suppression engine using OpenAI GPT."""
    
    def __init__(self):
        """Initialize AI suppression engine."""
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        
        # Initialize OpenAI client if enabled
        if self.config.enable_gpt and self.config.openai_api_key:
            try:
                openai.api_key = self.config.openai_api_key
                self.client = openai.OpenAI(api_key=self.config.openai_api_key)
                self.available = True
                self.logger.info("OpenAI client initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize OpenAI client: {e}")
                self.available = False
        else:
            self.available = False
            if self.config.enable_gpt and not self.config.openai_api_key:
                self.logger.warning("ENABLE_GPT=true but OPENAI_API_KEY not set")
    
    def process_findings(self, findings: List[Dict], code: str) -> List[Dict]:
        """
        Process findings with AI to adjust confidence and identify false positives.
        
        Args:
            findings: List of findings
            code: Source code
            
        Returns:
            List[Dict]: Processed findings
        """
        if not self.available or not findings:
            return findings
        
        try:
            # Build prompt
            prompt = self._build_prompt(findings, code)
            
            # Call OpenAI API
            response = self._call_openai(prompt)
            
            # Process response
            processed_findings = self._process_ai_response(findings, response)
            
            return processed_findings
            
        except Exception as e:
            self.logger.error(f"Error in AI processing: {e}")
            return findings
    
    def _build_prompt(self, findings: List[Dict], code: str) -> str:
        """
        Build prompt for OpenAI API.
        
        Args:
            findings: List of findings
            code: Source code
            
        Returns:
            str: Formatted prompt
        """
        # Truncate code if too long
        max_code_length = 8000  # Leave room for findings and instructions
        if len(code) > max_code_length:
            code = code[:max_code_length] + "\n... (truncated)"
        
        # Build findings summary
        findings_text = ""
        for i, finding in enumerate(findings):
            findings_text += f"""
Finding {i+1}:
- CWE: {finding.get('cwe_id', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- Line: {finding.get('line', 'Unknown')}
- Title: {finding.get('title', 'Unknown')}
- Snippet: {finding.get('snippet', 'Unknown')}
- Confidence: {finding.get('confidence', 'Unknown')}
"""
        
        prompt = f"""You are a security code analysis expert. Analyze the following C code and security findings to identify potential false positives and adjust confidence levels.

Code:
```c
{code}
```

Security Findings:
{findings_text}

Instructions:
1. Review each finding and determine if it's a true positive or false positive
2. For each finding, provide:
   - "action": "suppress", "adjust_confidence", or "keep"
   - "reason": Brief explanation
   - "new_confidence": "low", "medium", or "high" (if adjusting)
   - "finding_id": The finding number (1, 2, etc.)

3. NEVER suppress findings involving these functions: strcpy, strcat, gets, sprintf, vsprintf, system, popen
4. Be conservative - only suppress when you're very confident it's a false positive
5. Consider context, bounds checking, and safe coding patterns

Respond in JSON format:
{{
  "findings": [
    {{
      "finding_id": 1,
      "action": "suppress",
      "reason": "Safe printf with literal format string",
      "new_confidence": null
    }}
  ]
}}

JSON Response:"""
        
        return prompt
    
    def _call_openai(self, prompt: str) -> Optional[str]:
        """
        Call OpenAI API.
        
        Args:
            prompt: Prompt to send
            
        Returns:
            Optional[str]: API response
        """
        try:
            response = self.client.chat.completions.create(
                model=self.config.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security code analysis expert. Provide accurate, conservative analysis of security findings."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,  # Low temperature for consistent results
                max_tokens=2000,
                timeout=30
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            return None
    
    def _process_ai_response(self, findings: List[Dict], response: Optional[str]) -> List[Dict]:
        """
        Process AI response and apply changes to findings.
        
        Args:
            findings: Original findings
            response: AI response
            
        Returns:
            List[Dict]: Processed findings
        """
        if not response:
            return findings
        
        try:
            import json
            ai_data = json.loads(response)
            
            # Process each AI recommendation
            for ai_finding in ai_data.get('findings', []):
                finding_id = ai_finding.get('finding_id')
                action = ai_finding.get('action')
                reason = ai_finding.get('reason', '')
                new_confidence = ai_finding.get('new_confidence')
                
                # Find corresponding finding (1-based to 0-based)
                if finding_id and 1 <= finding_id <= len(findings):
                    finding = findings[finding_id - 1]
                    
                    # Check safety gates
                    if self._should_never_suppress(finding):
                        continue
                    
                    # Apply action
                    if action == 'suppress':
                        finding['status'] = 'SUPPRESSED'
                        finding['suppression_reason'] = f"ai_suppression: {reason}"
                    elif action == 'adjust_confidence' and new_confidence:
                        finding['confidence'] = new_confidence
                        finding['suppression_reason'] = f"ai_adjustment: {reason}"
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing AI response: {e}")
        except Exception as e:
            self.logger.error(f"Error processing AI response: {e}")
        
        return findings
    
    def _should_never_suppress(self, finding: Dict) -> bool:
        """Check if finding should never be suppressed by AI."""
        snippet = finding.get('snippet', '')
        
        # Check for never-suppress functions
        never_suppress_funcs = [
            "strcpy", "strcat", "gets", "sprintf", "vsprintf", 
            "system", "popen"
        ]
        
        for func in never_suppress_funcs:
            if func in snippet:
                return True
        
        return False


# Global AI engine instance
_ai_engine = None


def get_ai_engine() -> AISuppressionEngine:
    """Get the global AI engine instance."""
    global _ai_engine
    
    if _ai_engine is None:
        _ai_engine = AISuppressionEngine()
    
    return _ai_engine


def process_findings_with_ai(findings: List[Dict], code: str) -> List[Dict]:
    """
    Process findings with AI to adjust confidence and identify false positives.
    
    Args:
        findings: List of findings
        code: Source code
        
    Returns:
        List[Dict]: Processed findings
    """
    engine = get_ai_engine()
    return engine.process_findings(findings, code)


def is_ai_available() -> bool:
    """
    Check if AI processing is available.
    
    Returns:
        bool: True if AI is available
    """
    engine = get_ai_engine()
    return engine.available
