#!/usr/bin/env python3
"""
Test script to check backend startup
"""

import sys
import os
import asyncio

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

async def test_startup():
    try:
        print("Testing backend startup...")
        
        # Import the app
        from app.main import app
        
        print("✓ App imported successfully")
        
        # Test startup event
        print("Testing startup event...")
        await app.router.startup()
        print("✓ Startup event completed")
        
        print("\nBackend startup test passed!")
        
    except Exception as e:
        print(f"✗ Startup error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_startup())
