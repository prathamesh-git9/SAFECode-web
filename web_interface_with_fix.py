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

# HTML template for the web interface with auto-fix - StealthWriter.ai inspired design
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAFECode-Web - AI-Powered Code Security Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #000000;
            --text-secondary: #333333;
            --text-muted: #666666;
            --border-color: #e0e0e0;
            --accent-color: #000000;
            --success-color: #28a745;
            --error-color: #dc3545;
            --warning-color: #ffc107;
            --export-color: #007bff;
        }
        
        [data-theme="dark"] {
            --bg-primary: #000000;
            --bg-secondary: #111111;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #888888;
            --border-color: #333333;
            --accent-color: #ffffff;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 16px;
        }
        
        .navbar {
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 0;
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .nav-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .logo-icon {
            font-size: 2rem;
            color: var(--accent-color);
        }
        
        .nav-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }
        
        .nav-menu-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            transition: color 0.2s;
        }
        
        .nav-menu-link:hover {
            color: var(--text-primary);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            color: var(--text-primary);
        }
        
        .header p {
            font-size: 1.1rem;
            color: var(--text-muted);
            max-width: 600px;
            margin: 0 auto;
        }
        
        .theme-toggle {
            position: absolute;
            top: 0;
            right: 0;
            background: none;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 0.9rem;
        }
        
        .theme-toggle:hover {
            background-color: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }
        
        .input-section {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 25px;
        }
        
        .code-input-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .code-input {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        
        .code-output {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            display: none;
        }
        
        .output-section {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 25px;
        }
        
        .section-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 15px;
            color: var(--text-primary);
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        textarea {
            width: 100%;
            padding: 12px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            color: var(--text-primary);
            min-height: 400px;
            resize: vertical;
            line-height: 1.5;
        }
        
        textarea:focus {
            outline: none;
            border-color: var(--accent-color);
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 10px 20px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            flex: 1;
        }
        
        .btn:hover {
            background-color: var(--bg-secondary);
        }
        
                 .btn-primary {
             background-color: var(--text-primary);
             color: var(--bg-primary);
             border-color: var(--text-primary);
         }
         
         .btn-primary:hover {
             background-color: var(--text-secondary);
             border-color: var(--text-secondary);
             color: var(--bg-primary);
         }
        
        .btn-export {
            background-color: var(--export-color);
            color: white;
            border-color: var(--export-color);
        }
        
        .btn-export:hover {
            opacity: 0.9;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 2px solid var(--border-color);
            border-top: 2px solid var(--accent-color);
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
            margin-top: 20px;
        }
        
        .summary {
            margin-bottom: 20px;
        }
        
        .summary h3 {
            color: var(--text-primary);
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .stat-item {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        
        .stat-number {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            display: block;
        }
        
        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        
        .findings {
            margin-top: 20px;
        }
        
        .findings h3 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1.1rem;
        }
        
        .findings-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        
        .finding {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
        }
        
        .finding-title {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .severity {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 500;
            margin-bottom: 8px;
            display: inline-block;
        }
        
        .severity.critical {
            background-color: var(--error-color);
            color: white;
        }
        
        .severity.high {
            background-color: var(--warning-color);
            color: black;
        }
        
        .severity.medium {
            background-color: #ffc107;
            color: black;
        }
        
        .severity.low {
            background-color: var(--success-color);
            color: white;
        }
        
        .finding-details {
            color: var(--text-secondary);
            font-size: 0.8rem;
            line-height: 1.4;
        }
        
        .code-content {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.8rem;
            color: var(--text-primary);
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            min-height: 400px;
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            max-width: 300px;
        }
        
        .notification.success {
            background-color: var(--success-color);
        }
        
        .notification.error {
            background-color: var(--error-color);
        }
        
        .notification.warning {
            background-color: var(--warning-color);
            color: black;
        }
        
                 .notification.info {
             background-color: var(--text-muted);
         }
         
         .file-input-wrapper {
             position: relative;
             width: 100%;
         }
         
         .file-input {
             position: absolute;
             opacity: 0;
             width: 100%;
             height: 100%;
             cursor: pointer;
             z-index: 2;
         }
         
         .file-input-label {
             display: flex;
             align-items: center;
             gap: 10px;
             padding: 12px 16px;
             background-color: var(--bg-primary);
             border: 2px dashed var(--border-color);
             border-radius: 8px;
             cursor: pointer;
             transition: all 0.2s ease;
             color: var(--text-secondary);
             font-size: 14px;
             font-weight: 500;
         }
         
         .file-input-label:hover {
             border-color: var(--accent-color);
             background-color: var(--bg-secondary);
             color: var(--text-primary);
         }
         
         .file-input-icon {
             font-size: 1.2rem;
         }
         
         .file-input-text {
             flex: 1;
         }
         
         .file-input:focus + .file-input-label {
             border-color: var(--accent-color);
             box-shadow: 0 0 0 2px rgba(0, 0, 0, 0.1);
         }
         
         @media (max-width: 1024px) {
            .findings-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .code-input-container {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            .findings-grid {
                grid-template-columns: 1fr;
            }
            
            .theme-toggle {
                position: static;
                margin: 0 auto 20px;
                width: fit-content;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="nav-logo">
                <span>SAFECode</span>
            </a>
            <div class="nav-menu">
                <a href="/how-to-use" class="nav-menu-link">How to Use</a>
                <a href="/login" class="nav-menu-link">Login</a>
                <a href="/signup" class="nav-menu-link">Sign Up</a>
                <button class="theme-toggle" onclick="toggleTheme()">
                    <span id="theme-icon">🌙</span>
                </button>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="header">
            <h1>SAFECode-Web</h1>
            <p>AI-Powered Code Security Scanner with Advanced Vulnerability Detection and Auto-Fix</p>
        </div>
        
        <div class="main-content">
            <div class="input-section">
                <h2 class="section-title">Code Analysis</h2>
                <div class="code-input-container">
                    <div class="code-input">
                        <div class="form-group">
                            <label for="code">C/C++ Code</label>
                            <button class="btn" onclick="clearCode()" style="margin-bottom: 10px; width: 100%;">Clear</button>
                            <textarea id="code" placeholder="Paste your C/C++ code here...">#include <stdio.h>
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
}</textarea>
                        </div>
                        <div class="form-group">
                            <label for="fileInput">Or Upload a File</label>
                            <div class="file-input-wrapper">
                                <input type="file" id="fileInput" accept=".c,.cpp,.h,.hpp,.cc,.cxx" class="file-input">
                                <label for="fileInput" class="file-input-label">
                                    <span class="file-input-icon">📁</span>
                                    <span class="file-input-text">Choose C/C++ file</span>
                                </label>
                            </div>
                        </div>
                        <div class="button-group">
                            <button class="btn btn-primary" onclick="scanCode()">Scan for Vulnerabilities</button>
                            <button class="btn btn-primary" id="fixBtn" onclick="autoFixCode()" style="display: none;">Fix Code</button>
                        </div>
                                                 <div style="margin-top: 10px; font-size: 0.8rem; color: var(--text-muted);">
                             <strong>Keyboard Shortcuts:</strong> Ctrl+Enter (Scan) | Ctrl+Shift+F (Fix) | Ctrl+K (Clear) | Ctrl+O (Choose File)
                         </div>
                    </div>
                    <div class="code-output" id="codeOutput">
                        <h3>Fixed Code</h3>
                        <button class="btn btn-export" id="exportBtn" onclick="exportReport()" style="display: none; margin-bottom: 15px; width: 100%;">
                            Export Report
                        </button>
                        <div class="code-content" id="fixedCodeContent"></div>
                        <button class="btn" id="copyBtn" onclick="copyFixedCode()" style="display: none; margin-top: 10px;">
                            Copy Fixed Code
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="output-section">
                <h2 class="section-title">Analysis Results</h2>
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>Analyzing code for vulnerabilities...</p>
                </div>
                
                <div class="results" id="results">
                    <div class="summary" id="summary"></div>
                    <div class="findings" id="findings"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Theme management
        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            
            const themeIcon = document.getElementById('theme-icon');
            const themeText = document.getElementById('theme-text');
            
            if (theme === 'light') {
                themeIcon.textContent = '🌙';
                themeText.textContent = 'Dark Mode';
            } else {
                themeIcon.textContent = '☀️';
                themeText.textContent = 'Light Mode';
            }
        }
        
        function toggleTheme() {
            const currentTheme = localStorage.getItem('theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            setTheme(newTheme);
        }
        
        // Initialize theme
        setTheme(localStorage.getItem('theme') || 'dark');
        
        // Add file input change listener
        document.addEventListener('DOMContentLoaded', function() {
            const fileInput = document.getElementById('fileInput');
            if (fileInput) {
                fileInput.addEventListener('change', function() {
                    if (this.files.length > 0) {
                        loadFile();
                    }
                });
            }
        });
        
        function scanCode() {
            try {
                console.log('🔍 Scan button clicked!');
                const code = document.getElementById('code').value;
                console.log('📝 Code length:', code.length);
                
                if (!code.trim()) {
                    alert('Please enter some code to scan.');
                    return;
                }
                
                console.log('🚀 Starting scan...');
                
                // Show loading
                document.getElementById('loading').style.display = 'block';
                document.getElementById('results').style.display = 'none';
                document.getElementById('codeOutput').style.display = 'none';
                
                fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        filename: 'code.c',
                        code: code
                    })
                })
                .then(response => {
                    console.log('📡 Scan response status:', response.status);
                    return response.json();
                })
                .then(data => {
                    console.log('📊 Scan data received:', data);
                    document.getElementById('loading').style.display = 'none';
                    displayResults(data);
                })
                .catch(error => {
                    console.error('❌ Scan error:', error);
                    document.getElementById('loading').style.display = 'none';
                    alert('Error: Failed to scan code');
                });
            } catch (error) {
                console.error('❌ Scan function error:', error);
                alert('Error in scan function: ' + error.message);
            }
        }
        
        function displayResults(data) {
            console.log('📊 Displaying results:', data);
            const resultsDiv = document.getElementById('results');
            const summaryDiv = document.getElementById('summary');
            const findingsDiv = document.getElementById('findings');
            const outputSection = document.getElementById('codeOutput');
            
            // Display summary
            const totalFindings = data.findings.length;
            const activeFindings = data.findings.length;
            const suppressedFindings = 0;
            const suppressionRate = 0;
            
            console.log('📈 Summary stats:', {totalFindings, activeFindings, suppressedFindings, suppressionRate});
            
            summaryDiv.innerHTML = `
                <h3>Scan Summary</h3>
                <div class="stat-item">
                    <span class="stat-number">${totalFindings}</span>
                    <span class="stat-label">Total Findings</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">${activeFindings}</span>
                    <span class="stat-label">Active Issues</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">${suppressedFindings}</span>
                    <span class="stat-label">Suppressed</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">${suppressionRate}%</span>
                    <span class="stat-label">Suppression Rate</span>
                </div>
            `;
            
            // Display findings in 3-column grid
            findingsDiv.innerHTML = '<h3>Vulnerability Analysis</h3>';
            
            if (data.findings.length === 0) {
                findingsDiv.innerHTML += '<p style="color: var(--success-color); text-align: center; padding: 20px;">No vulnerabilities detected!</p>';
            } else {
                findingsDiv.innerHTML += '<div class="findings-grid">';
                data.findings.forEach(finding => {
                    const severityClass = finding.severity.toLowerCase();
                    findingsDiv.innerHTML += `
                        <div class="finding">
                            <div class="finding-title">${finding.title}</div>
                            <span class="severity ${severityClass}">${finding.severity}</span>
                            <div class="finding-details">
                                <strong>CWE:</strong> ${finding.cwe_id}<br>
                                <strong>Line:</strong> ${finding.line}<br>
                                ${finding.snippet}
                            </div>
                        </div>
                    `;
                });
                findingsDiv.innerHTML += '</div>';
            }
            
            resultsDiv.style.display = 'block';
            outputSection.style.display = 'block';
            console.log('✅ Results displayed');
            
            // Show fix button if there are findings
            const fixBtn = document.getElementById('fixBtn');
            if (data.findings.length > 0) {
                fixBtn.style.display = 'block';
                console.log('🔧 Fix button shown');
            } else {
                fixBtn.style.display = 'none';
                console.log('🔧 Fix button hidden');
            }
        }
        
        function autoFixCode() {
            console.log('🔧 Fix button clicked!');
            const code = document.getElementById('code').value;
            console.log('📝 Code to fix length:', code.length);
            
            // Get findings from the current results
            const findings = Array.from(document.querySelectorAll('.finding')).map(finding => {
                const title = finding.querySelector('.finding-title').textContent;
                const severity = finding.querySelector('.severity').textContent;
                const details = finding.querySelector('.finding-details').textContent;
                
                // Extract CWE from details
                const cweMatch = details.match(/CWE: ([^\\n]+)/);
                const cwe = cweMatch ? cweMatch[1].trim() : 'CWE-120';
                
                // Extract line from details
                const lineMatch = details.match(/Line: ([0-9]+)/);
                const line = lineMatch ? parseInt(lineMatch[1]) : 1;
                
                return {
                    id: Math.random().toString(36).substr(2, 9),
                    cwe_id: cwe,
                    title: title,
                    severity: severity,
                    line: line
                };
            });
            
            console.log('🔍 Found findings:', findings.length);
            
            if (findings.length === 0) {
                alert('No vulnerabilities to fix.');
                return;
            }
            
            console.log('🚀 Starting fix...');
            
            // Show loading
            document.getElementById('loading').style.display = 'block';
            document.getElementById('loading').innerHTML = `
                <div class="spinner"></div>
                <p>Applying AI-powered fixes...</p>
            `;
            
            fetch('/fix', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    filename: 'code.c',
                    code: code,
                    findings: findings
                })
            })
            .then(response => {
                console.log('📡 Fix response status:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('🔧 Fix data received:', data);
                document.getElementById('loading').style.display = 'none';
                displayFixResults(data);
            })
            .catch(error => {
                console.error('❌ Fix error:', error);
                document.getElementById('loading').style.display = 'none';
                alert('Error: Failed to fix code');
                console.error('Error:', error);
            });
        }
        
        function displayFixResults(data) {
            const codeOutputDiv = document.getElementById('codeOutput');
            const fixedCodeContentDiv = document.getElementById('fixedCodeContent');
            const copyBtn = document.getElementById('copyBtn');
            const exportBtn = document.getElementById('exportBtn');
            
            codeOutputDiv.style.display = 'block';
            fixedCodeContentDiv.textContent = data.fixed_code;
            copyBtn.style.display = 'block';
            exportBtn.style.display = 'block';
        }
        
        function copyFixedCode() {
            try {
                const fixedCode = document.getElementById('fixedCodeContent').textContent;
                navigator.clipboard.writeText(fixedCode).then(() => {
                    showNotification('Fixed code copied to clipboard!', 'success');
                }).catch(() => {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = fixedCode;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showNotification('Fixed code copied to clipboard!', 'success');
                });
            } catch (error) {
                console.error('❌ Copy error:', error);
                showNotification('Failed to copy code', 'error');
            }
        }
        
        function clearCode() {
            try {
                console.log('🗑️ Clear button clicked!');
                document.getElementById('code').value = '';
                document.getElementById('results').style.display = 'none';
                document.getElementById('codeOutput').style.display = 'none';
                document.getElementById('fixBtn').style.display = 'none';
                document.getElementById('copyBtn').style.display = 'none';
                document.getElementById('exportBtn').style.display = 'none';
                console.log('✅ Code cleared successfully');
            } catch (error) {
                console.error('❌ Clear function error:', error);
                alert('Error in clear function: ' + error.message);
            }
        }
        
        function loadFile() {
            try {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];
                
                if (!file) {
                    showNotification('Please select a file first', 'error');
                    return;
                }
                
                // Check file extension
                const allowedExtensions = ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'];
                const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
                
                if (!allowedExtensions.includes(fileExtension)) {
                    showNotification('Please select a valid C/C++ file (.c, .cpp, .h, .hpp, .cc, .cxx)', 'error');
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(e) {
                    const content = e.target.result;
                    document.getElementById('code').value = content;
                    showNotification(`File "${file.name}" loaded successfully!`, 'success');
                    console.log(`📁 File loaded: ${file.name} (${content.length} characters)`);
                };
                
                reader.onerror = function() {
                    showNotification('Error reading file', 'error');
                };
                
                reader.readAsText(file);
                
            } catch (error) {
                console.error('❌ Load file error:', error);
                showNotification('Error loading file: ' + error.message, 'error');
            }
        }
        
        function exportReport() {
            try {
                const findings = Array.from(document.querySelectorAll('.finding')).map(finding => {
                    const title = finding.querySelector('.finding-title').textContent;
                    const severity = finding.querySelector('.severity').textContent;
                    const details = finding.querySelector('.finding-details').textContent;
                    
                    const cweMatch = details.match(/CWE: ([^\\n]+)/);
                    const cwe = cweMatch ? cweMatch[1].trim() : 'N/A';
                    
                    const lineMatch = details.match(/Line: ([0-9]+)/);
                    const line = lineMatch ? parseInt(lineMatch[1]) : 1;
                    
                    return {
                        title: title,
                        severity: severity,
                        cwe: cwe,
                        line: line,
                        details: details
                    };
                });

                const summary = document.getElementById('summary').textContent;
                const findingsHtml = document.getElementById('findings').innerHTML;
                const fixedCode = document.getElementById('fixedCodeContent').textContent;

                const reportContent = `
                    <h2>SAFECode-Web Report</h2>
                    <p>Generated on: ${new Date().toISOString()}</p>
                    <h3>Scan Summary</h3>
                    ${summary}
                    <h3>Vulnerability Analysis</h3>
                    ${findingsHtml}
                    <h3>Fixed Code</h3>
                    <pre>${fixedCode}</pre>
                `;

                const blob = new Blob([reportContent], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'safecode_report.html';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification('Report exported successfully!', 'success');
            } catch (error) {
                console.error('❌ Export error:', error);
                showNotification('Failed to export report', 'error');
            }
        }
        
        // Notification system
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            
            document.body.appendChild(notification);
            
            // Auto remove after 3 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 3000);
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl+Enter to scan
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                console.log('⌨️ Keyboard shortcut: Ctrl+Enter (Scan)');
                scanCode();
            }
            
            // Ctrl+Shift+F to fix
            if (e.ctrlKey && e.shiftKey && e.key === 'F') {
                e.preventDefault();
                console.log('⌨️ Keyboard shortcut: Ctrl+Shift+F (Fix)');
                const fixBtn = document.getElementById('fixBtn');
                if (fixBtn.style.display !== 'none') {
                    autoFixCode();
                } else {
                    showNotification('No vulnerabilities found to fix', 'warning');
                }
            }
            
            // Ctrl+K to clear
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                console.log('⌨️ Keyboard shortcut: Ctrl+K (Clear)');
                clearCode();
            }
            
            // Ctrl+O to load file
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                console.log('⌨️ Keyboard shortcut: Ctrl+O (Load File)');
                document.getElementById('fileInput').click();
            }
        });
    </script>
</body>
</html>
"""

# Page templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SAFECode-Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #000000;
            --text-secondary: #333333;
            --text-muted: #666666;
            --border-color: #e0e0e0;
            --accent-color: #000000;
            --success-color: #28a745;
            --error-color: #dc3545;
        }
        
        [data-theme="dark"] {
            --bg-primary: #000000;
            --bg-secondary: #111111;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #888888;
            --border-color: #333333;
            --accent-color: #ffffff;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .navbar {
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 0;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .nav-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .logo-icon {
            font-size: 2rem;
            color: var(--accent-color);
        }
        
        .nav-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }
        
        .nav-menu-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .nav-menu-link:hover {
            color: var(--text-primary);
        }
        
        .container {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
        }
        
        .form-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
        }
        
        .form-title {
            text-align: center;
            margin-bottom: 30px;
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-size: 14px;
        }
        
        input:focus {
            outline: none;
            border-color: var(--accent-color);
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            background-color: var(--text-primary);
            color: var(--bg-primary);
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            margin-bottom: 15px;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .form-footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .form-footer a {
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .form-footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="nav-logo">
                <span>SAFECode</span>
            </a>
            <div class="nav-menu">
                <a href="/how-to-use" class="nav-menu-link">How to Use</a>
                <a href="/login" class="nav-menu-link">Login</a>
                <a href="/signup" class="nav-menu-link">Sign Up</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="form-card">
            <h2 class="form-title">Login</h2>
            <form>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
                <div class="form-footer">
                    Don't have an account? <a href="/signup">Sign up</a>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""

SIGNUP_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - SAFECode-Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #000000;
            --text-secondary: #333333;
            --text-muted: #666666;
            --border-color: #e0e0e0;
            --accent-color: #000000;
            --success-color: #28a745;
            --error-color: #dc3545;
        }
        
        [data-theme="dark"] {
            --bg-primary: #000000;
            --bg-secondary: #111111;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #888888;
            --border-color: #333333;
            --accent-color: #ffffff;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .navbar {
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 0;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .nav-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .logo-icon {
            font-size: 2rem;
            color: var(--accent-color);
        }
        
        .nav-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }
        
        .nav-menu-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .nav-menu-link:hover {
            color: var(--text-primary);
        }
        
        .container {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
        }
        
        .form-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
        }
        
        .form-title {
            text-align: center;
            margin-bottom: 30px;
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-size: 14px;
        }
        
        input:focus {
            outline: none;
            border-color: var(--accent-color);
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            background-color: var(--text-primary);
            color: var(--bg-primary);
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            margin-bottom: 15px;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .form-footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .form-footer a {
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .form-footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="nav-logo">
                <span>SAFECode</span>
            </a>
            <div class="nav-menu">
                <a href="/how-to-use" class="nav-menu-link">How to Use</a>
                <a href="/login" class="nav-menu-link">Login</a>
                <a href="/signup" class="nav-menu-link">Sign Up</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="form-card">
            <h2 class="form-title">Sign Up</h2>
            <form>
                <div class="form-group">
                    <label for="name">Full Name</label>
                    <input type="text" id="name" name="name" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="confirm-password">Confirm Password</label>
                    <input type="password" id="confirm-password" name="confirm-password" required>
                </div>
                <button type="submit" class="btn">Create Account</button>
                <div class="form-footer">
                    Already have an account? <a href="/login">Login</a>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
"""

HOW_TO_USE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>How to Use - SAFECode-Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --text-primary: #000000;
            --text-secondary: #333333;
            --text-muted: #666666;
            --border-color: #e0e0e0;
            --accent-color: #000000;
        }
        
        [data-theme="dark"] {
            --bg-primary: #000000;
            --bg-secondary: #111111;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #888888;
            --border-color: #333333;
            --accent-color: #ffffff;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .navbar {
            background-color: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 0;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .nav-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .logo-icon {
            font-size: 2rem;
            color: var(--accent-color);
        }
        
        .nav-menu {
            display: flex;
            gap: 30px;
            align-items: center;
        }
        
        .nav-menu-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .nav-menu-link:hover {
            color: var(--text-primary);
        }
        
        .container {
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        
        .content-card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 40px;
        }
        
        .page-title {
            text-align: center;
            margin-bottom: 40px;
            font-size: 2rem;
            font-weight: 600;
        }
        
        .step {
            margin-bottom: 30px;
            padding: 20px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        
        .step-number {
            display: inline-block;
            width: 30px;
            height: 30px;
            background-color: var(--accent-color);
            color: var(--bg-primary);
            border-radius: 50%;
            text-align: center;
            line-height: 30px;
            font-weight: 600;
            margin-right: 15px;
        }
        
        .step-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--text-primary);
        }
        
        .step-description {
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        .code-example {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }
        
        .keyboard-shortcuts {
            margin-top: 30px;
            padding: 20px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        
        .shortcut {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .shortcut:last-child {
            border-bottom: none;
        }
        
        .shortcut-key {
            font-weight: 600;
            color: var(--accent-color);
        }
        
        .shortcut-description {
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <a href="/" class="nav-logo">
                <span>SAFECode</span>
            </a>
            <div class="nav-menu">
                <a href="/how-to-use" class="nav-menu-link">How to Use</a>
                <a href="/login" class="nav-menu-link">Login</a>
                <a href="/signup" class="nav-menu-link">Sign Up</a>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <div class="content-card">
            <h1 class="page-title">How to Use SAFECode-Web</h1>
            
            <div class="step">
                <span class="step-number">1</span>
                <div class="step-title">Paste Your Code</div>
                <div class="step-description">
                    Copy and paste your C/C++ code into the text area on the main page. You can also upload a file using the file input.
                </div>
                <div class="code-example">
// Example C code with vulnerabilities
#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

int main() {
    char buffer[10];
    char *user_input = "This is a very long string";
    strcpy(buffer, user_input); // Vulnerable to buffer overflow
    return 0;
}
                </div>
            </div>
            
            <div class="step">
                <span class="step-number">2</span>
                <div class="step-title">Scan for Vulnerabilities</div>
                <div class="step-description">
                    Click the "Scan for Vulnerabilities" button to analyze your code. The system will detect security issues and display them in a grid layout.
                </div>
            </div>
            
            <div class="step">
                <span class="step-number">3</span>
                <div class="step-title">Review Findings</div>
                <div class="step-description">
                    Review the detected vulnerabilities, their severity levels, and the specific lines of code that need attention.
                </div>
            </div>
            
            <div class="step">
                <span class="step-number">4</span>
                <div class="step-title">Auto-Fix with AI</div>
                <div class="step-description">
                    Click the "Fix Code" button to automatically fix the vulnerabilities using AI-powered suggestions. The fixed code will appear in the right panel.
                </div>
            </div>
            
            <div class="step">
                <span class="step-number">5</span>
                <div class="step-title">Export and Share</div>
                <div class="step-description">
                    Use the "Export Report" button to download a comprehensive HTML report of your scan results and fixes.
                </div>
            </div>
            
            <div class="keyboard-shortcuts">
                <h3>Keyboard Shortcuts</h3>
                <div class="shortcut">
                    <span class="shortcut-key">Ctrl + Enter</span>
                    <span class="shortcut-description">Scan for vulnerabilities</span>
                </div>
                <div class="shortcut">
                    <span class="shortcut-key">Ctrl + Shift + F</span>
                    <span class="shortcut-description">Auto-fix code</span>
                </div>
                <div class="shortcut">
                    <span class="shortcut-key">Ctrl + K</span>
                    <span class="shortcut-description">Clear code</span>
                </div>
                <div class="shortcut">
                    <span class="shortcut-key">Ctrl + O</span>
                    <span class="shortcut-description">Load file</span>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Main page with the web interface."""
    # Check backend status
    backend_status = "🟢 Online" if check_backend_status() else "🔴 Offline"
    return render_template_string(HTML_TEMPLATE, backend_status=backend_status)

@app.route('/login')
def login():
    """Login page."""
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/signup')
def signup():
    """Sign up page."""
    return render_template_string(SIGNUP_TEMPLATE)

@app.route('/how-to-use')
def how_to_use():
    """How to use page."""
    return render_template_string(HOW_TO_USE_TEMPLATE)

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
