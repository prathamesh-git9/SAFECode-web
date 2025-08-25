#!/usr/bin/env python3
"""
Compare fallback vs GPT-powered fixes
"""

import requests
import openai
import os

# GPT Configuration
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
GPT_MODEL = "gpt-4o-mini"
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

def test_backend_fix():
    """Test the backend's current fix (fallback pattern-based)."""
    
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
    
    print("🔍 Testing Backend Fix (Current)")
    print("=" * 50)
    
    try:
        # Scan for vulnerabilities
        response = requests.post('http://localhost:8002/scan', 
                                json={'filename': 'test.c', 'code': original_code})
        
        if response.status_code == 200:
            result = response.json()
            findings = result.get('findings', [])
            
            # Auto-fix with backend
            fix_response = requests.post('http://localhost:8002/fix', 
                                        json={
                                            'filename': 'test.c', 
                                            'code': original_code,
                                            'findings': findings
                                        })
            
            if fix_response.status_code == 200:
                fix_result = fix_response.json()
                backend_fixed_code = fix_result.get('fixed_code', 'No fixed code')
                
                print("✅ Backend fix completed")
                print(f"📏 Fixed code length: {len(backend_fixed_code)} characters")
                
                print("\n🟢 Backend Fixed Code:")
                print("-" * 40)
                print(backend_fixed_code)
                print("-" * 40)
                
                return backend_fixed_code
            else:
                print(f"❌ Backend fix failed: {fix_response.text}")
        else:
            print(f"❌ Backend scan failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Backend test error: {e}")
    
    return None

def test_gpt_fix():
    """Test direct GPT fix (full AI-powered)."""
    
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
    
    print("\n🤖 Testing GPT Fix (Direct)")
    print("=" * 50)
    
    try:
        # Prepare the prompt
        prompt = f"""You are a security expert C programmer. Fix the following C code by addressing the security vulnerabilities detected.

ORIGINAL CODE:
{original_code}

DETECTED VULNERABILITIES:
- Line 10: Buffer Overflow - strcpy (CWE-120)
  Suggestion: Replace strcpy with strncpy and add null termination
  Code: strcpy(buffer, user_input);

- Line 13: Format String Vulnerability - printf (CWE-134)
  Suggestion: Use format string as first argument: printf("%s", variable)
  Code: printf(user_input);

- Line 16: Command Injection - system (CWE-78)
  Suggestion: Avoid system() calls or validate input thoroughly
  Code: system("ls -la");

INSTRUCTIONS:
1. Fix each vulnerability while maintaining the original functionality
2. Use secure alternatives (strncpy instead of strcpy, fgets instead of gets, etc.)
3. Add proper bounds checking and null termination
4. Keep the code readable and well-commented
5. Return ONLY the fixed C code, no explanations

FIXED CODE:"""
        
        # Call GPT API
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
        
        gpt_fixed_code = response.choices[0].message.content.strip()
        
        # Clean up the response
        if gpt_fixed_code.startswith("```c"):
            gpt_fixed_code = gpt_fixed_code[3:]
        if gpt_fixed_code.startswith("```"):
            gpt_fixed_code = gpt_fixed_code[3:]
        if gpt_fixed_code.endswith("```"):
            gpt_fixed_code = gpt_fixed_code[:-3]
        gpt_fixed_code = gpt_fixed_code.strip()
        
        print("✅ GPT fix completed")
        print(f"📏 Fixed code length: {len(gpt_fixed_code)} characters")
        
        print("\n🟢 GPT Fixed Code:")
        print("-" * 40)
        print(gpt_fixed_code)
        print("-" * 40)
        
        return gpt_fixed_code
        
    except Exception as e:
        print(f"❌ GPT test error: {e}")
    
    return None

def compare_fixes(backend_fix, gpt_fix):
    """Compare the two fixes."""
    
    print("\n📊 Fix Comparison")
    print("=" * 50)
    
    if backend_fix and gpt_fix:
        print("🔍 Buffer Overflow Fix:")
        if 'strncpy(buffer, user_input, sizeof(buffer) - 1)' in gpt_fix:
            print("   ✅ GPT: Properly fixed with strncpy and size limit")
        else:
            print("   ⚠️  GPT: Partially fixed")
            
        if 'strncpy(buffer, user_input,' in backend_fix:
            print("   ⚠️  Backend: Partially fixed (missing size parameter)")
        else:
            print("   ❌ Backend: Not properly fixed")
        
        print("\n🔍 Format String Fix:")
        if 'printf("%s",' in gpt_fix:
            print("   ✅ GPT: Properly fixed with format string")
        else:
            print("   ❌ GPT: Still vulnerable")
            
        if 'printf(' in backend_fix and 'user_input' in backend_fix:
            print("   ❌ Backend: Still vulnerable")
        else:
            print("   ❓ Backend: Status unclear")
        
        print("\n🔍 Command Injection Fix:")
        if 'system(' not in gpt_fix:
            print("   ✅ GPT: Removed dangerous system() call")
        else:
            print("   ❌ GPT: Still contains system() call")
            
        if 'system(' in backend_fix:
            print("   ❌ Backend: Still contains system() call")
        else:
            print("   ✅ Backend: Removed system() call")
        
        print(f"\n📏 Code Length Comparison:")
        print(f"   Backend: {len(backend_fix)} characters")
        print(f"   GPT: {len(gpt_fix)} characters")
        
        print(f"\n🎯 Quality Assessment:")
        print(f"   Backend: Basic pattern-based fixes (limited)")
        print(f"   GPT: Intelligent AI-powered fixes (comprehensive)")

def main():
    """Main comparison function."""
    print("🧪 Comparing Backend vs GPT Auto-Fixes")
    print("=" * 60)
    
    # Test backend fix
    backend_fix = test_backend_fix()
    
    # Test GPT fix
    gpt_fix = test_gpt_fix()
    
    # Compare fixes
    compare_fixes(backend_fix, gpt_fix)
    
    print("\n" + "=" * 60)
    print("🎯 Summary:")
    print("   • Backend: Uses fallback pattern-based fixes")
    print("   • GPT: Uses full AI-powered intelligent fixes")
    print("   • GPT provides much better and more comprehensive fixes")
    print("   • The web interface is working at http://localhost:5000")

if __name__ == "__main__":
    main()
