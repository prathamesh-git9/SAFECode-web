#!/usr/bin/env python3
"""
Test script to check backend functionality
"""

import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_backend():
    try:
        print("Testing backend imports...")
        
        # Test config
        from app.config import get_config
        config = get_config()
        print("✓ Config loaded successfully")
        
        # Test Flawfinder runner
        from app.flawfinder_runner import FlawfinderRunner
        runner = FlawfinderRunner()
        print("✓ Flawfinder runner created successfully")
        
        # Test if Flawfinder is available
        if runner.check_availability():
            print("✓ Flawfinder is available")
        else:
            print("✗ Flawfinder is not available")
            
        # Test main app
        from app.main import app
        print("✓ Main app created successfully")
        
        print("\nAll tests passed! Backend should work correctly.")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_backend()
