#!/usr/bin/env python3
"""
Test script for SAFECode-Web Auto-Fix functionality
"""

import requests
import json

def test_scan():
    """Test the scan endpoint."""
    test_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello World");
    printf(buffer);
    return 0;
}"""
    
    print("Testing scan endpoint...")
    response = requests.post('http://localhost:8002/scan', 
                            json={'filename': 'test.c', 'code': test_code})
    
    print(f'Status: {response.status_code}')
    if response.status_code == 200:
        result = response.json()
        print(f'Found {len(result.get("findings", []))} vulnerabilities')
        return result
    else:
        print(f'Error: {response.text}')
        return None

def test_fix(scan_result):
    """Test the fix endpoint."""
    if not scan_result or not scan_result.get('findings'):
        print("No vulnerabilities to fix")
        return
    
    test_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello World");
    printf(buffer);
    return 0;
}"""
    
    print("\nTesting fix endpoint...")
    response = requests.post('http://localhost:8002/fix', 
                            json={
                                'filename': 'test.c', 
                                'code': test_code,
                                'findings': scan_result['findings']
                            })
    
    print(f'Status: {response.status_code}')
    if response.status_code == 200:
        result = response.json()
        print(f'Fix summary: {result.get("summary", "No summary")}')
        print(f'Original code length: {len(result.get("original_code", ""))}')
        print(f'Fixed code length: {len(result.get("fixed_code", ""))}')
        return result
    else:
        print(f'Error: {response.text}')
        return None

if __name__ == "__main__":
    print("🧪 Testing SAFECode-Web Auto-Fix System")
    print("=" * 50)
    
    # Test scan
    scan_result = test_scan()
    
    # Test fix if vulnerabilities found
    if scan_result:
        fix_result = test_fix(scan_result)
    
    print("\n✅ Test completed!")
