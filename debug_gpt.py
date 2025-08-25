#!/usr/bin/env python3
"""
Debug script to test the exact GPT API call from the backend
"""

import openai
import os

# Use the same configuration as the backend
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
GPT_MODEL = "gpt-4o-mini"

# Set environment variable for OpenAI
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

def test_backend_gpt_call():
    """Test the exact GPT API call that the backend makes."""
    
    # Original vulnerable code (same as in test)
    original_code = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char buffer[10];
    char *user_input = "This is a very long string that will cause a buffer overflow";
    
    // Vulnerable: buffer overflow
    strcpy(buffer, user_input);
    
    // Vulnerable: format string
    printf(user_input);
    
    // Vulnerable: command injection
    system("ls -la");
    
    return 0;
}"""
    
    # Mock findings (same as backend would have)
    findings = [
        {
            'line': 10,
            'title': 'Buffer Overflow - strcpy',
            'cwe_id': 'CWE-120',
            'snippet': '    strcpy(buffer, user_input);',
            'fix_hint': 'Replace strcpy with strncpy and add null termination'
        },
        {
            'line': 13,
            'title': 'Format String Vulnerability - printf',
            'cwe_id': 'CWE-134',
            'snippet': '    printf(user_input);',
            'fix_hint': 'Use format string as first argument: printf("%s", variable)'
        },
        {
            'line': 16,
            'title': 'Command Injection - system',
            'cwe_id': 'CWE-78',
            'snippet': '    system("ls -la");',
            'fix_hint': 'Avoid system() calls or validate input thoroughly'
        }
    ]
    
    print("🧪 Testing Backend GPT Call")
    print("=" * 50)
    
    # Prepare the prompt exactly as the backend does
    findings_text = ""
    for finding in findings:
        findings_text += f"- Line {finding['line']}: {finding['title']} ({finding['cwe_id']})\n"
        findings_text += f"  Suggestion: {finding.get('fix_hint', 'Fix this vulnerability')}\n"
        findings_text += f"  Code: {finding['snippet']}\n\n"
    
    prompt = f"""You are a security expert C programmer. Fix the following C code by addressing the security vulnerabilities detected.

ORIGINAL CODE:
{original_code}

DETECTED VULNERABILITIES:
{findings_text}

INSTRUCTIONS:
1. Fix each vulnerability while maintaining the original functionality
2. Use secure alternatives (strncpy instead of strcpy, fgets instead of gets, etc.)
3. Add proper bounds checking and null termination
4. Keep the code readable and well-commented
5. Return ONLY the fixed C code, no explanations

FIXED CODE:"""
    
    print("📝 Prompt prepared successfully")
    print(f"📏 Prompt length: {len(prompt)} characters")
    
    try:
        print("\n🤖 Calling GPT API...")
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[
                {"role": "system", "content": "You are a security expert C programmer. Provide only the fixed code without explanations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2000
        )
        
        fixed_code = response.choices[0].message.content.strip()
        
        # Clean up the response (remove markdown if present)
        if fixed_code.startswith("```c"):
            fixed_code = fixed_code[3:]
        if fixed_code.startswith("```"):
            fixed_code = fixed_code[3:]
        if fixed_code.endswith("```"):
            fixed_code = fixed_code[:-3]
        fixed_code = fixed_code.strip()
        
        print("✅ GPT API call successful!")
        print(f"📏 Fixed code length: {len(fixed_code)} characters")
        
        print("\n🟢 Fixed Code:")
        print("-" * 40)
        print(fixed_code)
        print("-" * 40)
        
        # Analyze the fix quality
        print("\n📊 Fix Quality Analysis:")
        
        # Check for proper strncpy usage
        if 'strncpy(buffer, user_input, sizeof(buffer) - 1)' in fixed_code:
            print("   ✅ Buffer overflow: Properly fixed with strncpy and size limit")
        elif 'strncpy(buffer, user_input,' in fixed_code:
            print("   ⚠️  Buffer overflow: Partially fixed with strncpy")
        else:
            print("   ❌ Buffer overflow: Not properly fixed")
        
        # Check for format string fix
        if 'printf("%s", user_input)' in fixed_code:
            print("   ✅ Format string: Properly fixed with format string")
        elif 'printf(' in fixed_code and 'user_input' in fixed_code:
            print("   ❌ Format string: Still vulnerable")
        else:
            print("   ❓ Format string: Status unclear")
        
        # Check for command injection fix
        if 'system(' not in fixed_code:
            print("   ✅ Command injection: Removed dangerous system() call")
        else:
            print("   ❌ Command injection: Still contains system() call")
        
    except Exception as e:
        print(f"❌ GPT API error: {e}")
        print(f"Error type: {type(e).__name__}")

if __name__ == "__main__":
    test_backend_gpt_call()
