#!/usr/bin/env python3
"""
Fix the auto-fix issue by starting the correct servers
"""

import subprocess
import time
import requests
import os
import signal
import sys

def kill_python_processes():
    """Kill all Python processes."""
    try:
        subprocess.run(["taskkill", "/f", "/im", "python.exe"], capture_output=True)
        subprocess.run(["taskkill", "/f", "/im", "python3.12.exe"], capture_output=True)
        print("✅ Killed existing Python processes")
    except:
        pass

def start_backend():
    """Start the backend with auto-fix."""
    print("🚀 Starting backend with GPT Auto-Fix...")
    backend_process = subprocess.Popen([
        sys.executable, "simple_working_backend_with_fix.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return backend_process

def start_web_interface():
    """Start the web interface with auto-fix."""
    print("🌐 Starting web interface with Auto-Fix...")
    web_process = subprocess.Popen([
        sys.executable, "web_interface_with_fix.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return web_process

def wait_for_server(url, timeout=30):
    """Wait for server to be ready."""
    print(f"⏳ Waiting for {url} to be ready...")
    for i in range(timeout):
        try:
            response = requests.get(url, timeout=1)
            if response.status_code == 200:
                print(f"✅ {url} is ready!")
                return True
        except:
            pass
        time.sleep(1)
    print(f"❌ {url} failed to start")
    return False

def test_auto_fix():
    """Test the auto-fix functionality."""
    print("\n🧪 Testing auto-fix functionality...")
    
    test_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello World");
    printf(buffer);
    return 0;
}"""
    
    try:
        # Test scan
        response = requests.post('http://localhost:8002/scan', 
                                json={'filename': 'test.c', 'code': test_code})
        
        if response.status_code == 200:
            result = response.json()
            findings = result.get('findings', [])
            print(f"✅ Scan found {len(findings)} vulnerabilities")
            
            # Test fix
            fix_response = requests.post('http://localhost:8002/fix', 
                                        json={
                                            'filename': 'test.c', 
                                            'code': test_code,
                                            'findings': findings
                                        })
            
            if fix_response.status_code == 200:
                fix_result = fix_response.json()
                print(f"✅ Auto-fix working! Summary: {fix_result.get('summary', 'No summary')}")
                return True
            else:
                print(f"❌ Fix failed: {fix_response.text}")
        else:
            print(f"❌ Scan failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    return False

def main():
    """Main function to fix the auto-fix issue."""
    print("🔧 Fixing SAFECode-Web Auto-Fix Issue")
    print("=" * 50)
    
    # Kill existing processes
    kill_python_processes()
    time.sleep(2)
    
    # Start backend
    backend_process = start_backend()
    time.sleep(3)
    
    # Wait for backend
    if not wait_for_server("http://localhost:8002/health"):
        print("❌ Backend failed to start")
        backend_process.terminate()
        return
    
    # Start web interface
    web_process = start_web_interface()
    time.sleep(3)
    
    # Wait for web interface
    if not wait_for_server("http://localhost:5000"):
        print("❌ Web interface failed to start")
        backend_process.terminate()
        web_process.terminate()
        return
    
    # Test auto-fix
    if test_auto_fix():
        print("\n🎉 SUCCESS! Auto-fix is working!")
        print("\n📋 Instructions:")
        print("1. Go to http://localhost:5000")
        print("2. Paste vulnerable C code")
        print("3. Click '🔍 Scan for Vulnerabilities'")
        print("4. Click '🤖 Auto-Fix with GPT' (appears after scan)")
        print("5. See the side-by-side comparison!")
        
        print("\n🔍 How to verify you're using the correct interface:")
        print("- Look for 'Version 3.0' at the bottom (not 2.0)")
        print("- Look for '🔧 Fix Endpoint: http://localhost:8002/fix' in startup message")
        print("- The auto-fix button appears AFTER scanning for vulnerabilities")
        
        print("\n⏹️  Press Ctrl+C to stop servers")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping servers...")
            backend_process.terminate()
            web_process.terminate()
            print("✅ Servers stopped")
    else:
        print("❌ Auto-fix test failed")
        backend_process.terminate()
        web_process.terminate()

if __name__ == "__main__":
    main()
