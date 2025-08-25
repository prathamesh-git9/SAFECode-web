#!/usr/bin/env python3
"""
Simple C Code Security Analyzer and Fixer
=========================================

This script:
1. Takes C code as input
2. Uses Flawfinder to find vulnerabilities
3. Uses GPT to fix the vulnerabilities
4. Shows the fixed code

Usage:
    python simple_sast_fixer.py
"""

import subprocess
import tempfile
import os
import json
import sys
from typing import List, Dict, Tuple

# Configuration
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"  # Your key
GPT_MODEL = "gpt-4o-mini"

def check_flawfinder():
    """Check if Flawfinder is available."""
    try:
        result = subprocess.run(['flawfinder', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False

def install_flawfinder():
    """Install Flawfinder if not available."""
    print("Installing Flawfinder...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'flawfinder'], 
                      check=True)
        print("Flawfinder installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install Flawfinder. Please install manually:")
        print("pip install flawfinder")
        return False

def analyze_code(code: str, filename: str = "code.c") -> List[Dict]:
    """Analyze C code using Flawfinder."""
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as f:
            f.write(code)
            temp_file = f.name

        # Run Flawfinder
        cmd = ['flawfinder', '--csv', '--context', '--dataonly', temp_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        vulnerabilities = []
        if result.returncode == 0:
            # Parse CSV output
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and not line.startswith('File,'):  # Skip header
                    parts = line.split(',')
                    if len(parts) >= 6:
                        try:
                            vuln = {
                                'line': int(parts[1]),  # Line is second column
                                'level': parts[4],      # Level is fifth column
                                'category': parts[5],   # Category is sixth column
                                'description': parts[7], # Warning is eighth column
                                'suggestion': parts[8] if len(parts) > 8 else "",  # Suggestion is ninth column
                                'severity': get_severity(int(parts[4])),
                                'cwe': get_cwe(parts[5])
                            }
                            vulnerabilities.append(vuln)
                        except (ValueError, IndexError) as e:
                            print(f"Error parsing line: {line}, error: {e}")
                            continue

        # Clean up
        os.unlink(temp_file)
        return vulnerabilities

    except Exception as e:
        print(f"Error analyzing code: {e}")
        return []

def get_severity(level: int) -> str:
    """Convert Flawfinder level to severity."""
    if level >= 5:
        return "critical"
    elif level >= 4:
        return "high"
    elif level >= 3:
        return "medium"
    elif level >= 2:
        return "low"
    else:
        return "info"

def get_cwe(category: str) -> str:
    """Map category to CWE."""
    mapping = {
        'buffer': 'CWE-120',
        'format': 'CWE-134',
        'shell': 'CWE-78',
        'tob': 'CWE-190',
        'race': 'CWE-367'
    }
    return mapping.get(category.lower(), 'CWE-20')

def fix_code_with_gpt(code: str, vulnerabilities: List[Dict]) -> str:
    """Fix code using GPT."""
    try:
        import openai
        
        # Initialize OpenAI client
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        
        # Build prompt
        prompt = f"""Fix the following C code vulnerabilities:

Original Code:
```c
{code}
```

Vulnerabilities found:
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            prompt += f"""
{i}. {vuln['category'].title()} vulnerability (Line {vuln['line']})
   - CWE: {vuln['cwe']}
   - Severity: {vuln['severity']}
   - Description: {vuln['description']}
   - Suggestion: {vuln['suggestion']}
"""

        prompt += """

Instructions:
1. Fix all security vulnerabilities
2. Maintain code functionality
3. Use secure alternatives (e.g., strncpy instead of strcpy)
4. Add proper bounds checking
5. Return only the complete fixed C code
6. Include necessary headers
7. Ensure the code compiles and works correctly

Fixed Code:
```c
"""
        
        # Call GPT
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a C security expert. Fix security vulnerabilities in C code. Return only the fixed code, no explanations."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=4000
        )
        
        fixed_code = response.choices[0].message.content.strip()
        
        # Extract code from markdown if present
        if fixed_code.startswith('```c'):
            fixed_code = fixed_code[4:]
        if fixed_code.endswith('```'):
            fixed_code = fixed_code[:-3]
        
        return fixed_code.strip()
        
    except ImportError:
        print("OpenAI library not installed. Installing...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'openai'], check=True)
        return fix_code_with_gpt(code, vulnerabilities)  # Retry
    except Exception as e:
        print(f"Error fixing code with GPT: {e}")
        return code

def main():
    """Main function."""
    print("🔒 C Code Security Analyzer and Fixer")
    print("=" * 50)
    
    # Check/install Flawfinder
    if not check_flawfinder():
        if not install_flawfinder():
            return
        if not check_flawfinder():
            print("Flawfinder still not available. Exiting.")
            return
    
    print("✅ Flawfinder is available")
    
    # Get C code from user
    print("\n📝 Enter your C code (press Ctrl+D or Ctrl+Z when done):")
    print("(Or paste your code and press Enter twice)")
    
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    
    if not lines:
        # Try getting input another way
        print("Paste your C code here:")
        code = input()
        lines = [code]
    
    code = '\n'.join(lines)
    
    if not code.strip():
        print("No code provided. Exiting.")
        return
    
    print(f"\n🔍 Analyzing code ({len(code)} characters)...")
    
    # Analyze code
    vulnerabilities = analyze_code(code)
    
    if not vulnerabilities:
        print("✅ No vulnerabilities found!")
        return
    
    print(f"\n⚠️  Found {len(vulnerabilities)} vulnerabilities:")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"{i}. {vuln['severity'].upper()}: {vuln['description']} (Line {vuln['line']})")
    
    # Ask user if they want to fix
    print(f"\n🤖 Fix vulnerabilities using GPT? (y/n): ", end="")
    try:
        response = input().lower().strip()
        if response not in ['y', 'yes']:
            print("Exiting without fixing.")
            return
    except (EOFError, KeyboardInterrupt):
        print("\nExiting without fixing.")
        return
    
    print("\n🔧 Fixing code with GPT...")
    
    # Fix code
    fixed_code = fix_code_with_gpt(code, vulnerabilities)
    
    print("\n✅ Fixed Code:")
    print("=" * 50)
    print(fixed_code)
    print("=" * 50)
    
    # Save to file
    try:
        with open('fixed_code.c', 'w', encoding='utf-8') as f:
            f.write(fixed_code)
        print(f"\n💾 Fixed code saved to 'fixed_code.c'")
    except Exception as e:
        print(f"Could not save file: {e}")

if __name__ == "__main__":
    main()
