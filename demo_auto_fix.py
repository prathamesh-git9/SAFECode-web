#!/usr/bin/env python3
"""
Demo script to show SAFECode-Web Auto-Fix functionality
"""

import requests
import json

def demo_auto_fix():
    """Demonstrate the auto-fix functionality."""
    
    # Test code with vulnerabilities
    test_code = """#include <stdio.h>
#include <string.h>

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
    
    print("🧪 SAFECode-Web Auto-Fix Demo")
    print("=" * 50)
    print("\n📝 Original Code (Vulnerable):")
    print("-" * 30)
    print(test_code)
    print("-" * 30)
    
    # Step 1: Scan for vulnerabilities
    print("\n🔍 Step 1: Scanning for vulnerabilities...")
    response = requests.post('http://localhost:8002/scan', 
                            json={'filename': 'demo.c', 'code': test_code})
    
    if response.status_code == 200:
        result = response.json()
        findings = result.get('findings', [])
        print(f"✅ Found {len(findings)} vulnerabilities:")
        
        for i, finding in enumerate(findings, 1):
            print(f"   {i}. {finding['title']} (Line {finding['line']}) - {finding['severity']}")
        
        # Step 2: Auto-fix the vulnerabilities
        print("\n🤖 Step 2: Auto-fixing with GPT...")
        fix_response = requests.post('http://localhost:8002/fix', 
                                    json={
                                        'filename': 'demo.c', 
                                        'code': test_code,
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
            print("-" * 30)
            print(fix_result.get('fixed_code', 'No fixed code'))
            print("-" * 30)
            
            print("\n🎯 How to use in the web interface:")
            print("1. Go to http://localhost:5000")
            print("2. Paste the vulnerable code above")
            print("3. Click '🔍 Scan for Vulnerabilities'")
            print("4. Click '🤖 Auto-Fix with GPT' (appears after scan)")
            print("5. See the side-by-side comparison!")
            
        else:
            print(f"❌ Fix failed: {fix_response.text}")
    else:
        print(f"❌ Scan failed: {response.text}")

if __name__ == "__main__":
    demo_auto_fix()
