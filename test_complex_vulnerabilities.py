#!/usr/bin/env python3
"""
Test complex vulnerabilities with enhanced GPT fixes
"""

import requests
import json

def test_complex_vulnerabilities():
    """Test the backend with complex vulnerable code."""
    
    # Complex vulnerable code with multiple issues
    complex_vulnerable_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_SIZE 100

void vulnerable_function(char *input) {
    char buffer[50];
    char command[200];
    strcpy(buffer, input);  // CWE-120: Buffer overflow
    strcat(buffer, " - dangerous");  // CWE-120: Buffer overflow
    printf(buffer);  // CWE-134: Format string
    sprintf(command, "ls -la %s", input);  // CWE-78: Command injection
    system(command);  // CWE-78: Command injection
    int size = strlen(input) * 2;  // CWE-190: Integer overflow
    char *dynamic_buffer = malloc(size);
    free(dynamic_buffer);
    strcpy(dynamic_buffer, "use after free");  // CWE-416: Use after free
    char *ptr = NULL;
    if (input[0] == 'A') {
        ptr = malloc(10);
    }
    strcpy(ptr, "null deref");  // CWE-476: Null pointer dereference
}

int main(int argc, char *argv[]) {
    char user_input[MAX_SIZE];
    gets(user_input);  // CWE-120: Buffer overflow
    vulnerable_function(user_input);
    char small_buffer[10];
    strcpy(small_buffer, "This is a very long string that will definitely overflow the buffer");
    char format_string[100];
    sprintf(format_string, "User said: %s", user_input);
    printf(format_string);  // CWE-134: Format string
    char system_command[300];
    sprintf(system_command, "echo 'User input: %s'", user_input);
    system(system_command);  // CWE-78: Command injection
    int index = strlen(user_input) * 2;
    char array[100];
    array[index] = 'X';  // CWE-190: Integer overflow leading to buffer overflow
    return 0;
}
"""
    
    print("🧪 Testing Complex Vulnerabilities with Enhanced GPT Fixes")
    print("=" * 60)
    
    # Step 1: Scan for vulnerabilities
    print("\n🔍 Step 1: Scanning for vulnerabilities...")
    scan_response = requests.post(
        "http://localhost:8002/scan",
        json={
            "filename": "complex_test.c",
            "code": complex_vulnerable_code
        }
    )
    
    if scan_response.status_code == 200:
        scan_data = scan_response.json()
        findings = scan_data.get("findings", [])
        print(f"✅ Found {len(findings)} vulnerabilities:")
        for i, finding in enumerate(findings, 1):
            print(f"   {i}. {finding.get('title', 'Unknown')} (Line {finding.get('line', '?')}) - {finding.get('severity', 'UNKNOWN')}")
    else:
        print(f"❌ Scan failed: {scan_response.status_code}")
        return
    
    # Step 2: Auto-fix with GPT
    print("\n🤖 Step 2: Auto-fixing with Enhanced GPT...")
    fix_response = requests.post(
        "http://localhost:8002/fix",
        json={
            "filename": "complex_test.c",
            "code": complex_vulnerable_code,
            "findings": findings
        }
    )
    
    if fix_response.status_code == 200:
        fix_data = fix_response.json()
        print(f"✅ Auto-fix completed successfully!")
        print(f"📊 Summary: {fix_data.get('summary', 'Unknown')}")
        print(f"🔒 Security Level: {fix_data.get('security_level', 'Unknown')}")
        print(f"📏 Fixed code length: {len(fix_data.get('fixed_code', ''))} characters")
        
        print(f"\n🔧 Fixes Applied:")
        for fix in fix_data.get('fixes_applied', []):
            print(f"   • Line {fix.get('line', 'Unknown')}: {fix.get('vulnerability', 'Unknown')} ({fix.get('cwe', 'Unknown')}) - {fix.get('severity', 'Unknown')}")
        
        print(f"\n🟢 Fixed Code:")
        print("-" * 40)
        print(fix_data.get('fixed_code', 'No fixed code available'))
        print("-" * 40)
        
        # Quality assessment
        fixed_code = fix_data.get('fixed_code', '')
        print(f"\n📊 Quality Assessment:")
        
        # Check for key improvements
        improvements = []
        if 'strncpy' in fixed_code and 'strcpy' not in fixed_code:
            improvements.append("✅ Buffer overflows fixed (strcpy → strncpy)")
        if 'printf("%s"' in fixed_code:
            improvements.append("✅ Format string vulnerabilities fixed")
        if 'system(' not in fixed_code or '// system(' in fixed_code:
            improvements.append("✅ Command injection vulnerabilities addressed")
        if 'fgets(' in fixed_code and 'gets(' not in fixed_code:
            improvements.append("✅ gets() replaced with fgets()")
        if 'snprintf(' in fixed_code and 'sprintf(' not in fixed_code:
            improvements.append("✅ sprintf() replaced with snprintf()")
        
        for improvement in improvements:
            print(f"   {improvement}")
        
        if fix_data.get('security_level') == 'enhanced':
            print("   🎯 Using enhanced GPT-powered fixes")
        else:
            print("   ⚠️ Using fallback pattern-based fixes")
            
    else:
        print(f"❌ Fix failed: {fix_response.status_code}")

if __name__ == "__main__":
    test_complex_vulnerabilities()
