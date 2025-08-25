#!/usr/bin/env python3
"""
Test script for the web interface
"""

import requests
import json

def test_web_interface():
    """Test the web interface endpoints"""
    
    # Test 1: Check if web interface is accessible
    try:
        response = requests.get('http://localhost:5000')
        print(f"✅ Web interface accessible: {response.status_code}")
    except Exception as e:
        print(f"❌ Web interface not accessible: {e}")
        return
    
    # Test 2: Test scan endpoint
    test_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "overflow");
    return 0;
}"""
    
    try:
        response = requests.post(
            'http://localhost:5000/scan',
            json={'filename': 'test.c', 'code': test_code},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Scan endpoint works: Found {len(data.get('findings', []))} vulnerabilities")
            
            # Test 3: Test fix endpoint if vulnerabilities found
            if data.get('findings'):
                findings = data['findings']
                fix_response = requests.post(
                    'http://localhost:5000/fix',
                    json={'filename': 'test.c', 'code': test_code, 'findings': findings},
                    headers={'Content-Type': 'application/json'}
                )
                
                if fix_response.status_code == 200:
                    fix_data = fix_response.json()
                    print(f"✅ Fix endpoint works: Fixed code length: {len(fix_data.get('fixed_code', ''))}")
                else:
                    print(f"❌ Fix endpoint failed: {fix_response.status_code}")
        else:
            print(f"❌ Scan endpoint failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error testing endpoints: {e}")

if __name__ == '__main__':
    print("🧪 Testing SAFECode-Web Interface...")
    test_web_interface()
    print("✅ Test completed!")
