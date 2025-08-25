#!/usr/bin/env python3
"""
Simple Web App for C Code Security Analysis and Fixing
======================================================

This provides a web interface for:
1. Pasting C code
2. Finding vulnerabilities with Flawfinder
3. Fixing them with GPT
4. Showing the fixed code

Usage:
    python simple_web_app.py
"""

from flask import Flask, render_template_string, request, jsonify
import subprocess
import tempfile
import os
import sys
from typing import List, Dict

app = Flask(__name__)

# Configuration
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
GPT_MODEL = "gpt-4o-mini"

def check_flawfinder():
    """Check if Flawfinder is available."""
    try:
        result = subprocess.run(['flawfinder', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False

def analyze_code(code: str) -> List[Dict]:
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
                        except (ValueError, IndexError):
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
        return "Error: OpenAI library not installed. Run: pip install openai"
    except Exception as e:
        return f"Error fixing code with GPT: {e}"

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C Code Security Analyzer & Fixer</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .panel {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .panel h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        textarea {
            width: 100%;
            height: 300px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            resize: vertical;
        }
        .buttons {
            margin: 15px 0;
            display: flex;
            gap: 10px;
        }
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        .btn-primary:hover {
            background-color: #2980b9;
        }
        .btn-success {
            background-color: #27ae60;
            color: white;
        }
        .btn-success:hover {
            background-color: #229954;
        }
        .btn-secondary {
            background-color: #95a5a6;
            color: white;
        }
        .btn-secondary:hover {
            background-color: #7f8c8d;
        }
        .vulnerabilities {
            margin-top: 15px;
        }
        .vuln-item {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin: 5px 0;
        }
        .vuln-critical { background: #f8d7da; border-color: #f5c6cb; }
        .vuln-high { background: #f8d7da; border-color: #f5c6cb; }
        .vuln-medium { background: #fff3cd; border-color: #ffeaa7; }
        .vuln-low { background: #d1ecf1; border-color: #bee5eb; }
        .loading {
            text-align: center;
            color: #666;
            font-style: italic;
        }
        .status {
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .status.success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .status.error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .example-btn {
            background-color: #6c757d;
            color: white;
            padding: 5px 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 C Code Security Analyzer & Fixer</h1>
        <p>Find and fix security vulnerabilities in C code using Flawfinder and GPT</p>
    </div>

    <div class="container">
        <div class="panel">
            <h2>📝 Input C Code</h2>
            <button class="example-btn" onclick="loadExample()">Load Example</button>
            <textarea id="inputCode" placeholder="Paste your C code here..."></textarea>
            <div class="buttons">
                <button class="btn-primary" onclick="analyzeCode()">🔍 Analyze Code</button>
                <button class="btn-success" onclick="fixCode()">🔧 Fix Code</button>
                <button class="btn-secondary" onclick="clearAll()">Clear All</button>
            </div>
            <div id="status"></div>
            <div id="vulnerabilities" class="vulnerabilities"></div>
        </div>

        <div class="panel">
            <h2>✅ Fixed Code</h2>
            <textarea id="outputCode" placeholder="Fixed code will appear here..." readonly></textarea>
            <div class="buttons">
                <button class="btn-primary" onclick="copyToClipboard()">📋 Copy to Clipboard</button>
                <button class="btn-secondary" onclick="downloadCode()">💾 Download</button>
            </div>
        </div>
    </div>

    <script>
        function loadExample() {
            const exampleCode = `#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char *input = "This is a very long string that will overflow the buffer";
    strcpy(buffer, input);  // CWE-120: Buffer overflow
    printf("%s", buffer);
    return 0;
}`;
            document.getElementById('inputCode').value = exampleCode;
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
        }

        function showLoading() {
            showStatus('Processing...', 'success');
        }

        function analyzeCode() {
            const code = document.getElementById('inputCode').value;
            if (!code.trim()) {
                showStatus('Please enter some C code to analyze.', 'error');
                return;
            }

            showLoading();
            
            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ code: code })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayVulnerabilities(data.vulnerabilities);
                    showStatus(`Found ${data.vulnerabilities.length} vulnerabilities.`, 'success');
                } else {
                    showStatus(data.error, 'error');
                }
            })
            .catch(error => {
                showStatus('Error analyzing code: ' + error, 'error');
            });
        }

        function fixCode() {
            const code = document.getElementById('inputCode').value;
            if (!code.trim()) {
                showStatus('Please enter some C code to fix.', 'error');
                return;
            }

            showLoading();
            
            fetch('/fix', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ code: code })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('outputCode').value = data.fixed_code;
                    displayVulnerabilities(data.vulnerabilities);
                    showStatus(`Fixed ${data.vulnerabilities.length} vulnerabilities.`, 'success');
                } else {
                    showStatus(data.error, 'error');
                }
            })
            .catch(error => {
                showStatus('Error fixing code: ' + error, 'error');
            });
        }

        function displayVulnerabilities(vulnerabilities) {
            const vulnDiv = document.getElementById('vulnerabilities');
            if (vulnerabilities.length === 0) {
                vulnDiv.innerHTML = '<div class="status success">✅ No vulnerabilities found!</div>';
                return;
            }

            let html = '<h3>⚠️ Vulnerabilities Found:</h3>';
            vulnerabilities.forEach((vuln, index) => {
                html += `
                    <div class="vuln-item vuln-${vuln.severity}">
                        <strong>${index + 1}. ${vuln.severity.toUpperCase()}: ${vuln.description}</strong><br>
                        <small>Line ${vuln.line} | CWE: ${vuln.cwe} | Category: ${vuln.category}</small><br>
                        <small><strong>Suggestion:</strong> ${vuln.suggestion}</small>
                    </div>
                `;
            });
            vulnDiv.innerHTML = html;
        }

        function copyToClipboard() {
            const outputCode = document.getElementById('outputCode');
            outputCode.select();
            document.execCommand('copy');
            showStatus('Code copied to clipboard!', 'success');
        }

        function downloadCode() {
            const outputCode = document.getElementById('outputCode').value;
            if (!outputCode.trim()) {
                showStatus('No code to download.', 'error');
                return;
            }

            const blob = new Blob([outputCode], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'fixed_code.c';
            a.click();
            window.URL.revokeObjectURL(url);
            showStatus('Code downloaded as fixed_code.c', 'success');
        }

        function clearAll() {
            document.getElementById('inputCode').value = '';
            document.getElementById('outputCode').value = '';
            document.getElementById('vulnerabilities').innerHTML = '';
            document.getElementById('status').innerHTML = '';
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        code = data.get('code', '')
        
        if not code.strip():
            return jsonify({'success': False, 'error': 'No code provided'})
        
        vulnerabilities = analyze_code(code)
        
        return jsonify({
            'success': True,
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/fix', methods=['POST'])
def fix():
    try:
        data = request.get_json()
        code = data.get('code', '')
        
        if not code.strip():
            return jsonify({'success': False, 'error': 'No code provided'})
        
        # First analyze
        vulnerabilities = analyze_code(code)
        
        if not vulnerabilities:
            return jsonify({
                'success': True,
                'vulnerabilities': [],
                'fixed_code': code,
                'message': 'No vulnerabilities found to fix.'
            })
        
        # Then fix
        fixed_code = fix_code_with_gpt(code, vulnerabilities)
        
        return jsonify({
            'success': True,
            'vulnerabilities': vulnerabilities,
            'fixed_code': fixed_code
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Check if Flawfinder is available
    if not check_flawfinder():
        print("❌ Flawfinder not found!")
        print("Install it with: pip install flawfinder")
        sys.exit(1)
    
    print("✅ Flawfinder is available")
    print("🌐 Starting web server...")
    print("📱 Open your browser to: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
