#!/usr/bin/env python3
"""
Test GPT-powered auto-fix functionality
"""

import requests
import json

def test_gpt_auto_fix():
    """Test the GPT-powered auto-fix with the same code you provided."""
    
    # Your original vulnerable code
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
    
    print("🧪 Testing GPT-Powered Auto-Fix")
    print("=" * 50)
    print("\n📝 Original Vulnerable Code:")
    print("-" * 40)
    print(original_code)
    print("-" * 40)
    
    # Step 1: Scan for vulnerabilities
    print("\n🔍 Step 1: Scanning for vulnerabilities...")
    response = requests.post('http://localhost:8002/scan', 
                            json={'filename': 'test.c', 'code': original_code})
    
    if response.status_code == 200:
        result = response.json()
        findings = result.get('findings', [])
        print(f"✅ Found {len(findings)} vulnerabilities:")
        
        for i, finding in enumerate(findings, 1):
            print(f"   {i}. {finding['title']} (Line {finding['line']}) - {finding['severity']}")
        
        # Step 2: Auto-fix with GPT
        print("\n🤖 Step 2: Auto-fixing with GPT...")
        fix_response = requests.post('http://localhost:8002/fix', 
                                    json={
                                        'filename': 'test.c', 
                                        'code': original_code,
                                        'findings': findings
                                    })
        
        if fix_response.status_code == 200:
            fix_result = fix_response.json()
            print("✅ Auto-fix completed successfully!")
            print(f"📊 Summary: {fix_result.get('summary', 'No summary')}")
            
            print("\n🔧 Fixes Applied:")
            for fix in fix_result.get('fixes_applied', []):
                print(f"   • Line {fix['line']}: {fix['vulnerability']} → {fix['fix']}")
            
            print("\n🟢 Fixed Code (Secure):")
            print("-" * 40)
            fixed_code = fix_result.get('fixed_code', 'No fixed code')
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
            
            print(f"\n📏 Code Length: Original {len(original_code)} chars → Fixed {len(fixed_code)} chars")
            
        else:
            print(f"❌ Fix failed: {fix_response.text}")
    else:
        print(f"❌ Scan failed: {response.text}")

if __name__ == "__main__":
    test_gpt_auto_fix()
