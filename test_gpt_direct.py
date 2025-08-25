#!/usr/bin/env python3
"""
Direct test of GPT API to see the exact error
"""

import openai
import os

# Set the API key
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

def test_gpt_direct():
    """Test GPT API directly."""
    print("🧪 Testing GPT API Directly")
    print("=" * 40)
    
    try:
        print("1. Testing OpenAI client initialization...")
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        print("   ✅ Client initialized successfully")
        
        print("2. Testing GPT API call...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'Hello World'"}],
            max_tokens=10
        )
        
        result = response.choices[0].message.content
        print(f"   ✅ GPT API working! Response: {result}")
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        print(f"   Error type: {type(e).__name__}")
        
        # Try alternative initialization
        try:
            print("\n3. Trying alternative initialization...")
            client = openai.OpenAI()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Say 'Hello World'"}],
                max_tokens=10
            )
            result = response.choices[0].message.content
            print(f"   ✅ Alternative method working! Response: {result}")
        except Exception as e2:
            print(f"   ❌ Alternative method also failed: {e2}")

if __name__ == "__main__":
    test_gpt_direct()
