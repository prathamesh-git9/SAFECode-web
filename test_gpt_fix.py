#!/usr/bin/env python3
"""
Test GPT-powered auto-fix functionality
"""

import requests
import json

def test_gpt_auto_fix():
    """Test the GPT-powered auto-fix functionality."""
    
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
    
    try:
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
                fixed_code = fix_result.get('fixed_code', 'No fixed code')
                summary = fix_result.get('summary', 'No summary')
                fixes_applied = fix_result.get('fixes_applied', [])
                security_level = fix_result.get('security_level', 'unknown')
                
                print(f"✅ Auto-fix completed successfully!")
                print(f"📊 Summary: {summary}")
                print(f"🔒 Security Level: {security_level}")
                print(f"📏 Fixed code length: {len(fixed_code)} characters")
                
                print("\n🔧 Fixes Applied:")
                for fix in fixes_applied:
                    print(f"   • Line {fix['line']}: {fix['vulnerability']} ({fix['cwe']}) - {fix['severity']}")
                
                print("\n🟢 Fixed Code:")
                print("-" * 40)
                print(fixed_code)
                print("-" * 40)
                
                # Quality assessment
                print("\n📊 Quality Assessment:")
                if 'strncpy' in fixed_code and 'strcpy' not in fixed_code:
                    print("   ✅ Buffer overflow fixed (strcpy → strncpy)")
                else:
                    print("   ⚠️ Buffer overflow fix unclear")
                
                if 'printf("%s"' in fixed_code:
                    print("   ✅ Format string vulnerability fixed")
                else:
                    print("   ⚠️ Format string fix unclear")
                
                if 'system(' not in fixed_code or '// system(' in fixed_code:
                    print("   ✅ Command injection vulnerability addressed")
                else:
                    print("   ⚠️ Command injection still present")
                
                if security_level == "enhanced":
                    print("   🎉 Enhanced GPT-powered fixes applied!")
                else:
                    print("   ⚠️ Using fallback pattern-based fixes")
                
            else:
                print(f"❌ Auto-fix failed: {fix_response.text}")
        else:
            print(f"❌ Scan failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Test error: {e}")

if __name__ == "__main__":
    test_gpt_auto_fix()
