#!/usr/bin/env python3
"""
SAFECode-Web Interface with Auto-Fix
A Flask web interface for pasting C code, getting vulnerability analysis, and auto-fixing with GPT.
"""

import requests
import json
from flask import Flask, render_template_string, request, jsonify
import os

app = Flask(__name__)

# Backend API configuration
BACKEND_URL = "http://localhost:8002"
API_TOKEN = "test-token"  # Default token from backend

# HTML template for the web interface with auto-fix
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAFECode-Web - C Code Vulnerability Scanner with Auto-Fix</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        input[type="text"], textarea {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            font-family: 'Courier New', monospace;
            transition: border-color 0.3s ease;
        }
        
        input[type="text"]:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        textarea {
            min-height: 300px;
            resize: vertical;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-success {
            background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
            color: white;
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(39, 174, 96, 0.3);
        }
        
        .btn-secondary {
            background: #95a5a6;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #7f8c8d;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c0392b;
        }
        
        .results {
            margin-top: 30px;
            border-top: 2px solid #ecf0f1;
            padding-top: 30px;
        }
        
        .vulnerability {
            background: #f8f9fa;
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .vulnerability.suppressed {
            border-left-color: #f39c12;
            background: #fef9e7;
        }
        
        .vulnerability.low {
            border-left-color: #3498db;
        }
        
        .vulnerability.medium {
            border-left-color: #f39c12;
        }
        
        .vulnerability.high {
            border-left-color: #e67e22;
        }
        
        .vulnerability.critical {
            border-left-color: #e74c3c;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vuln-title {
            font-weight: 600;
            font-size: 1.1em;
            color: #2c3e50;
        }
        
        .vuln-severity {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #3498db; color: white; }
        .severity-suppressed { background: #95a5a6; color: white; }
        
        .vuln-details {
            margin-bottom: 15px;
        }
        
        .vuln-detail {
            margin-bottom: 5px;
            font-size: 14px;
        }
        
        .vuln-detail strong {
            color: #2c3e50;
        }
        
        .code-snippet {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            margin-top: 10px;
        }
        
        .status {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .status.info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .summary {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .summary h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .stat-item {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-top: 5px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .footer {
            background: #ecf0f1;
            padding: 20px;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .code-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        
        .code-panel {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
        }
        
        .code-panel h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .code-display {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            min-height: 200px;
        }
        
        .fix-summary {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
        }
        
        .fixes-list {
            margin-top: 15px;
        }
        
        .fix-item {
            background: white;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 3px solid #27ae60;
        }
        
        .fix-item strong {
            color: #2c3e50;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SAFECode-Web</h1>
            <p>Advanced C/C++ Code Vulnerability Scanner with AI-Powered Auto-Fix</p>
        </div>
        
        <div class="content">
            <form id="scanForm">
                <div class="form-group">
                    <label for="filename">Filename:</label>
                    <input type="text" id="filename" name="filename" value="code.c" placeholder="Enter filename (e.g., main.c)">
                </div>
                
                <div class="form-group">
                    <label for="code">C/C++ Code:</label>
                    <textarea id="code" name="code" placeholder="Paste your C/C++ code here...&#10;&#10;Example:&#10;#include &lt;stdio.h&gt;&#10;#include &lt;string.h&gt;&#10;&#10;int main() {&#10;    char buffer[10];&#10;    strcpy(buffer, &quot;Hello World&quot;);&#10;    printf(&quot;%s\n&quot;, buffer);&#10;    return 0;&#10;}"></textarea>
                </div>
                
                <div class="button-group">
                    <button type="submit" class="btn btn-primary">🔍 Scan for Vulnerabilities</button>
                    <button type="button" class="btn btn-success" onclick="autoFixCode()" id="fixBtn" style="display: none;">🤖 Auto-Fix with GPT</button>
                    <button type="button" class="btn btn-secondary" onclick="clearForm()">🗑️ Clear</button>
                    <button type="button" class="btn btn-danger" onclick="loadExample()">📝 Load Example</button>
                </div>
            </form>
            
            <div id="loading" class="loading" style="display: none;">
                <div class="spinner"></div>
                <p>Analyzing your code for vulnerabilities...</p>
            </div>
            
            <div id="fixLoading" class="loading" style="display: none;">
                <div class="spinner"></div>
                <p>🤖 GPT is fixing your code...</p>
            </div>
            
            <div id="results" class="results" style="display: none;">
                <div id="status"></div>
                <div id="summary"></div>
                <div id="vulnerabilities"></div>
            </div>
            
            <div id="fixResults" class="results" style="display: none;">
                <div id="fixStatus"></div>
                <div id="codeComparison"></div>
            </div>
        </div>
        
        <div class="footer">
            <p>Powered by Flawfinder SAST + OpenAI GPT | Version 3.0 | Backend: {{ backend_status }}</p>
        </div>
    </div>

    <script>
        let currentFindings = [];
        let currentCode = "";
        
        async function scanCode() {
            const form = document.getElementById('scanForm');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const fixBtn = document.getElementById('fixBtn');
            const status = document.getElementById('status');
            const summary = document.getElementById('summary');
            const vulnerabilities = document.getElementById('vulnerabilities');
            
            const formData = new FormData(form);
            const data = {
                filename: formData.get('filename'),
                code: formData.get('code')
            };
            
            if (!data.code.trim()) {
                showStatus('Please enter some code to scan.', 'error');
                return;
            }
            
            currentCode = data.code;
            
            // Show loading
            loading.style.display = 'block';
            results.style.display = 'none';
            fixBtn.style.display = 'none';
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    currentFindings = result.findings;
                    displayResults(result);
                    
                    // Show fix button if vulnerabilities found
                    if (result.findings && result.findings.length > 0) {
                        fixBtn.style.display = 'inline-block';
                    }
                } else {
                    showStatus(`Error: ${result.detail || 'Failed to scan code'}`, 'error');
                }
            } catch (error) {
                showStatus(`Network error: ${error.message}`, 'error');
            } finally {
                loading.style.display = 'none';
                results.style.display = 'block';
            }
        }
        
        async function autoFixCode() {
            if (!currentFindings || currentFindings.length === 0) {
                showFixStatus('No vulnerabilities to fix.', 'info');
                return;
            }
            
            const fixLoading = document.getElementById('fixLoading');
            const fixResults = document.getElementById('fixResults');
            const fixStatus = document.getElementById('fixStatus');
            const codeComparison = document.getElementById('codeComparison');
            
            // Show loading
            fixLoading.style.display = 'block';
            fixResults.style.display = 'none';
            
            try {
                const response = await fetch('/fix', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        filename: document.getElementById('filename').value,
                        code: currentCode,
                        findings: currentFindings
                    })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    displayFixResults(result);
                } else {
                    showFixStatus(`Error: ${result.detail || 'Failed to fix code'}`, 'error');
                }
            } catch (error) {
                showFixStatus(`Network error: ${error.message}`, 'error');
            } finally {
                fixLoading.style.display = 'none';
                fixResults.style.display = 'block';
            }
        }
        
        function displayResults(data) {
            const status = document.getElementById('status');
            const summary = document.getElementById('summary');
            const vulnerabilities = document.getElementById('vulnerabilities');
            
            // Show status
            if (data.findings && data.findings.length > 0) {
                showStatus(`Found ${data.findings.length} potential vulnerabilities`, 'info');
            } else {
                showStatus('No vulnerabilities found! Your code appears to be secure.', 'success');
            }
            
            // Show summary
            if (data.summary) {
                displaySummary(data.summary);
            }
            
            // Show vulnerabilities
            if (data.findings && data.findings.length > 0) {
                displayVulnerabilities(data.findings);
            } else {
                vulnerabilities.innerHTML = '<p style="text-align: center; color: #27ae60; font-size: 1.2em;">✅ No vulnerabilities detected!</p>';
            }
        }
        
        function displayFixResults(data) {
            const fixStatus = document.getElementById('fixStatus');
            const codeComparison = document.getElementById('codeComparison');
            
            // Show fix status
            showFixStatus(data.summary, 'success');
            
            // Show code comparison
            codeComparison.innerHTML = `
                <div class="code-comparison">
                    <div class="code-panel">
                        <h3>🔴 Original Code (Vulnerable)</h3>
                        <div class="code-display">${escapeHtml(data.original_code)}</div>
                    </div>
                    <div class="code-panel">
                        <h3>🟢 Fixed Code (Secure)</h3>
                        <div class="code-display">${escapeHtml(data.fixed_code)}</div>
                    </div>
                </div>
                <div class="fix-summary">
                    <h4>🔧 Fixes Applied:</h4>
                    <div class="fixes-list">
                        ${data.fixes_applied.map(fix => `
                            <div class="fix-item">
                                <strong>Line ${fix.line}:</strong> ${fix.vulnerability} (${fix.cwe})<br>
                                <em>${fix.fix}</em>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        function displaySummary(summary) {
            const summaryDiv = document.getElementById('summary');
            const stats = summary.totals_by_severity || {};
            const total = Object.values(stats).reduce((a, b) => a + b, 0);
            const suppressed = summary.totals_by_status?.SUPPRESSED || 0;
            const active = total - suppressed;
            
            summaryDiv.innerHTML = `
                <div class="summary">
                    <h3>📊 Scan Summary</h3>
                    <div class="summary-stats">
                        <div class="stat-item">
                            <div class="stat-number">${total}</div>
                            <div class="stat-label">Total Findings</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">${active}</div>
                            <div class="stat-label">Active Issues</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">${suppressed}</div>
                            <div class="stat-label">Suppressed</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">${summary.suppression_rate ? (summary.suppression_rate * 100).toFixed(1) : 0}%</div>
                            <div class="stat-label">Suppression Rate</div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        function displayVulnerabilities(findings) {
            const vulnerabilitiesDiv = document.getElementById('vulnerabilities');
            
            vulnerabilitiesDiv.innerHTML = '<h3>🔍 Vulnerability Analysis</h3>';
            
            findings.forEach((finding, index) => {
                const severityClass = `severity-${finding.severity.toLowerCase()}`;
                const vulnClass = `vulnerability ${finding.status.toLowerCase()}`;
                
                const snippet = finding.snippet ? `<div class="code-snippet">${escapeHtml(finding.snippet)}</div>` : '';
                const suppressionReason = finding.suppression_reason ? `<div class="vuln-detail"><strong>Suppression Reason:</strong> ${finding.suppression_reason}</div>` : '';
                
                vulnerabilitiesDiv.innerHTML += `
                    <div class="${vulnClass}">
                        <div class="vuln-header">
                            <div class="vuln-title">${finding.title}</div>
                            <div class="vuln-severity ${severityClass}">${finding.severity}</div>
                        </div>
                        <div class="vuln-details">
                            <div class="vuln-detail"><strong>CWE:</strong> ${finding.cwe_id}</div>
                            <div class="vuln-detail"><strong>File:</strong> ${finding.file}</div>
                            <div class="vuln-detail"><strong>Line:</strong> ${finding.line}</div>
                            <div class="vuln-detail"><strong>Status:</strong> ${finding.status}</div>
                            <div class="vuln-detail"><strong>Confidence:</strong> ${(finding.confidence * 100).toFixed(1)}%</div>
                            ${suppressionReason}
                        </div>
                        ${snippet}
                    </div>
                `;
            });
        }
        
        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.innerHTML = `<div class="status ${type}">${message}</div>`;
        }
        
        function showFixStatus(message, type) {
            const fixStatus = document.getElementById('fixStatus');
            fixStatus.innerHTML = `<div class="status ${type}">${message}</div>`;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function clearForm() {
            document.getElementById('scanForm').reset();
            document.getElementById('results').style.display = 'none';
            document.getElementById('fixResults').style.display = 'none';
            document.getElementById('fixBtn').style.display = 'none';
            currentFindings = [];
            currentCode = "";
        }
        
        function loadExample() {
            const exampleCode = `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
}`;
            
            document.getElementById('code').value = exampleCode;
        }
        
        // Form submission
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            scanCode();
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main page with the web interface."""
    # Check backend status
    backend_status = "🟢 Online" if check_backend_status() else "🔴 Offline"
    return render_template_string(HTML_TEMPLATE, backend_status=backend_status)

@app.route('/scan', methods=['POST'])
def scan():
    """Handle code scanning requests."""
    try:
        data = request.get_json()
        filename = data.get('filename', 'code.c')
        code = data.get('code', '')
        
        if not code.strip():
            return jsonify({'error': 'No code provided'}), 400
        
        print(f"Scanning code for file: {filename}")
        print(f"Code length: {len(code)} characters")
        
        # Call the FastAPI backend
        response = requests.post(
            f"{BACKEND_URL}/scan",
            json={'filename': filename, 'code': code},
            headers={'Authorization': f'Bearer {API_TOKEN}'},
            timeout=30
        )
        
        print(f"Backend response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Scan completed successfully. Found {len(result.get('findings', []))} findings.")
            return jsonify(result)
        else:
            error_detail = "Unknown error"
            try:
                error_response = response.json()
                error_detail = error_response.get('detail', error_response.get('error', 'Unknown error'))
            except:
                error_detail = response.text[:200] if response.text else f"HTTP {response.status_code}"
            
            print(f"Backend error: {error_detail}")
            return jsonify({'error': f'Backend error: {error_detail}'}), 500
            
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        return jsonify({'error': 'Backend server is not running. Please start the backend first.'}), 503
    except requests.exceptions.Timeout as e:
        print(f"Timeout error: {e}")
        return jsonify({'error': 'Request timed out. The code might be too large or complex.'}), 408
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/fix', methods=['POST'])
def fix():
    """Handle code fixing requests."""
    try:
        data = request.get_json()
        filename = data.get('filename', 'code.c')
        code = data.get('code', '')
        findings = data.get('findings', [])
        
        if not code.strip():
            return jsonify({'error': 'No code provided'}), 400
        
        if not findings:
            return jsonify({'error': 'No vulnerabilities to fix'}), 400
        
        print(f"Fixing code for file: {filename}")
        print(f"Found {len(findings)} vulnerabilities to fix")
        
        # Call the FastAPI backend fix endpoint
        response = requests.post(
            f"{BACKEND_URL}/fix",
            json={'filename': filename, 'code': code, 'findings': findings},
            headers={'Authorization': f'Bearer {API_TOKEN}'},
            timeout=60
        )
        
        print(f"Fix response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Fix completed successfully.")
            return jsonify(result)
        else:
            error_detail = "Unknown error"
            try:
                error_response = response.json()
                error_detail = error_response.get('detail', error_response.get('error', 'Unknown error'))
            except:
                error_detail = response.text[:200] if response.text else f"HTTP {response.status_code}"
            
            print(f"Fix error: {error_detail}")
            return jsonify({'error': f'Fix error: {error_detail}'}), 500
            
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        return jsonify({'error': 'Backend server is not running. Please start the backend first.'}), 503
    except requests.exceptions.Timeout as e:
        print(f"Timeout error: {e}")
        return jsonify({'error': 'Request timed out. GPT processing might take longer.'}), 408
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

def check_backend_status():
    """Check if the backend is running."""
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

if __name__ == '__main__':
    print("🌐 Starting SAFECode-Web Interface with Auto-Fix...")
    print(f"📡 Backend URL: {BACKEND_URL}")
    print("🌍 Web Interface: http://localhost:5000")
    print("📚 API Documentation: http://localhost:8002/docs")
    print("🔧 Fix Endpoint: http://localhost:8002/fix")
    print("\n" + "="*50)
    print("🎯 Open your browser and go to: http://localhost:5000")
    print("📝 Paste your C/C++ code, scan for vulnerabilities, then click 'Auto-Fix with GPT'")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
