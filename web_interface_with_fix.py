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
    <title>SAFECode-Web - AI-Powered Code Security Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #000000;
            --bg-secondary: #111111;
            --bg-tertiary: #000000;
            --text-primary: #ffffff;
            --text-secondary: #cccccc;
            --text-muted: #888888;
            --border-color: #333333;
            --accent-color: #ffffff;
            --success-color: #00cc00;
            --error-color: #ff4444;
            --warning-color: #ff8800;
            --info-color: #ffcc00;
            --export-color: #4CAF50;
            --shadow-light: 0 2px 8px rgba(255, 255, 255, 0.1);
            --shadow-medium: 0 4px 16px rgba(255, 255, 255, 0.15);
            --shadow-heavy: 0 8px 32px rgba(255, 255, 255, 0.2);
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        [data-theme="light"] {
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-tertiary: #ffffff;
            --text-primary: #000000;
            --text-secondary: #333333;
            --text-muted: #666666;
            --border-color: #e0e0e0;
            --accent-color: #000000;
            --shadow-light: 0 2px 8px rgba(0, 0, 0, 0.1);
            --shadow-medium: 0 4px 16px rgba(0, 0, 0, 0.15);
            --shadow-heavy: 0 8px 32px rgba(0, 0, 0, 0.2);
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            transition: all 0.3s ease;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 60px;
            position: relative;
        }
        
        .header h1 {
            font-size: 3.5rem;
            font-weight: 700;
            margin-bottom: 20px;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px rgba(102, 126, 234, 0.5);
            letter-spacing: -2px;
        }
        
        .header p {
            font-size: 1.2rem;
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
            border-radius: 50px;
            padding: 8px 16px;
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .theme-toggle:hover {
            background-color: var(--bg-secondary);
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 40px;
            margin-bottom: 40px;
        }
        
        .input-section {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            box-shadow: var(--shadow-medium);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .code-input-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .code-input {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .code-output {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            display: none;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .output-section {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            box-shadow: var(--shadow-medium);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--text-primary);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        textarea {
            width: 100%;
            padding: 16px;
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            font-size: 14px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            color: var(--text-primary);
            transition: all 0.3s ease;
            min-height: 500px;
            resize: vertical;
            line-height: 1.5;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        textarea:focus {
            outline: none;
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.1), var(--shadow-medium);
            transform: scale(1.01);
        }
        
        .button-group {
            display: flex;
            gap: 12px;
            margin-top: 20px;
        }
        
        .btn {
            padding: 14px 24px;
            border: none;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex: 1;
            box-shadow: var(--shadow-light);
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: var(--gradient-primary);
            color: #ffffff;
            box-shadow: var(--shadow-medium);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-heavy);
        }
        
        .btn-secondary {
            background-color: var(--border-color);
            color: var(--text-primary);
            box-shadow: var(--shadow-light);
        }
        
        .btn-secondary:hover {
            background-color: var(--text-muted);
            transform: translateY(-1px);
            box-shadow: var(--shadow-medium);
        }
        
        .btn-export {
            background: var(--gradient-secondary);
            color: #ffffff;
            box-shadow: var(--shadow-medium);
        }
        
        .btn-export:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-heavy);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 3px solid var(--border-color);
            border-top: 3px solid var(--accent-color);
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .results {
            display: none;
            margin-top: 20px;
            animation: fadeIn 0.5s ease-out;
        }
        
        .finding {
            animation: fadeIn 0.3s ease-out;
        }
        
        .finding:nth-child(1) { animation-delay: 0.1s; }
        .finding:nth-child(2) { animation-delay: 0.2s; }
        .finding:nth-child(3) { animation-delay: 0.3s; }
        .finding:nth-child(4) { animation-delay: 0.4s; }
        .finding:nth-child(5) { animation-delay: 0.5s; }
        .finding:nth-child(6) { animation-delay: 0.6s; }
        
        .summary {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .summary h3 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1.1rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 12px;
        }
        
        .stat {
            text-align: center;
            padding: 15px;
            background-color: var(--bg-secondary);
            border-radius: 10px;
            box-shadow: var(--shadow-light);
            transition: all 0.3s ease;
        }
        
        .stat:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-medium);
        }
        
        .stat-number {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--text-primary);
            display: block;
        }
        
        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .findings {
            margin-top: 20px;
        }
        
        .findings h3 {
            color: var(--text-primary);
            margin-bottom: 20px;
            font-size: 1.1rem;
        }
        
        .findings-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }
        
        .finding {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px;
            transition: all 0.3s ease;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .finding:hover {
            transform: translateY(-3px);
            box-shadow: var(--shadow-heavy);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
            gap: 8px;
        }
        
        .finding-title {
            font-weight: 600;
            color: var(--text-primary);
            font-size: 0.85rem;
            line-height: 1.2;
            flex: 1;
        }
        
        .severity {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            white-space: nowrap;
            flex-shrink: 0;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .severity.critical {
            background: linear-gradient(135deg, #ff4444, #cc0000);
            color: #ffffff;
        }
        
        .severity.high {
            background: linear-gradient(135deg, #ff8800, #cc6600);
            color: #ffffff;
        }
        
        .severity.medium {
            background: linear-gradient(135deg, #ffcc00, #cc9900);
            color: #000000;
        }
        
        .severity.low {
            background: linear-gradient(135deg, #00cc00, #009900);
            color: #ffffff;
        }
        
        .finding-details {
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-bottom: 8px;
            line-height: 1.3;
        }
        
        .finding-snippet {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.7rem;
            color: var(--text-primary);
            overflow-x: auto;
            max-height: 100px;
            overflow-y: auto;
        }
        
        .fix-results {
            display: none;
            margin-top: 20px;
        }
        
        .code-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        
        .code-block {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        
        .code-block h4 {
            color: var(--text-primary);
            margin-bottom: 15px;
            font-size: 1rem;
        }
        
        .code-content {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 15px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            white-space: pre-wrap;
            overflow-x: auto;
            max-height: 500px;
            overflow-y: auto;
            min-height: 500px;
            box-shadow: var(--shadow-light);
            backdrop-filter: blur(5px);
        }
        
        .vulnerable-line {
            background-color: rgba(255, 68, 68, 0.2);
            border-left: 3px solid var(--error-color);
            padding-left: 10px;
            margin: 2px 0;
        }
        
        .safe-line {
            background-color: rgba(0, 204, 0, 0.1);
            border-left: 3px solid var(--success-color);
            padding-left: 10px;
            margin: 2px 0;
        }
        
        .status-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background-color: var(--bg-primary);
            border-top: 1px solid var(--border-color);
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9rem;
        }
        
        .status-left {
            color: var(--text-muted);
        }
        
        .status-right {
            color: var(--text-primary);
            font-weight: 600;
        }
        
        .status-online {
            color: var(--success-color);
        }
        
        .status-offline {
            color: var(--error-color);
        }
        
        @media (max-width: 1024px) {
            .findings-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .code-input-container {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2.5rem;
            }
            
            .code-comparison {
                grid-template-columns: 1fr;
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
    <div class="container">
        <div class="header">
            <button class="theme-toggle" onclick="toggleTheme()">
                <span id="theme-icon">🌙</span>
                <span id="theme-text">Dark Mode</span>
            </button>
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
                            <button class="btn btn-secondary" onclick="clearCode()" style="margin-bottom: 10px; width: 100%;">Clear</button>
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
                            <div style="display: flex; gap: 10px; align-items: center;">
                                <input type="file" id="fileInput" accept=".c,.cpp,.h,.hpp,.cc,.cxx" style="flex: 1; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-tertiary); color: var(--text-primary);">
                                <button class="btn btn-secondary" onclick="loadFile()" style="flex-shrink: 0;">📁 Load File</button>
                            </div>
                        </div>
                        <div class="button-group">
                            <button class="btn btn-primary" onclick="scanCode()">scan for vulnerabilities</button>
                            <button class="btn btn-primary" id="fixBtn" onclick="autoFixCode()" style="display: none;">Fix Code</button>
                        </div>
                        <div style="margin-top: 10px; font-size: 0.8rem; color: var(--text-muted);">
                            <strong>Keyboard Shortcuts:</strong> Ctrl+Enter (Scan) | Ctrl+Shift+F (Fix) | Ctrl+K (Clear) | Ctrl+O (Load File)
                        </div>
                    </div>
                    <div class="code-output" id="codeOutput">
                        <h3>Fixed Code</h3>
                        <button class="btn btn-export" id="exportBtn" onclick="exportReport()" style="display: none; margin-bottom: 15px; width: 100%;">
                            📄 Export Report
                        </button>
                        <div class="code-content" id="fixedCodeContent"></div>
                        <button class="btn btn-secondary" id="copyBtn" onclick="copyFixedCode()" style="display: none; margin-top: 10px;">
                            📋 Copy Fixed Code
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
    
    <div class="status-bar">
        <div class="status-left">
            Powered by Advanced AI Analysis | Version 5.1
        </div>
        <div class="status-right">
            Backend: <span id="backendStatus" class="status-offline">🔴 Offline</span>
        </div>
    </div>

    <script>
        // Theme management
        let currentTheme = localStorage.getItem('theme') || 'dark';
        
        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            currentTheme = theme;
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
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            setTheme(newTheme);
        }
        
        // Initialize theme
        setTheme(currentTheme);
        
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
        
        // Check backend status on page load
        window.onload = function() {
            console.log('🚀 Page loaded, checking backend status...');
            checkBackendStatus();
            
            // Test if buttons are accessible
            const scanBtn = document.querySelector('button[onclick="scanCode()"]');
            const clearBtn = document.querySelector('button[onclick="clearCode()"]');
            const fixBtn = document.getElementById('fixBtn');
            const exportBtn = document.getElementById('exportBtn');
            
            console.log('🔍 Button elements found:', {
                scanBtn: scanBtn ? 'Found' : 'Not found',
                clearBtn: clearBtn ? 'Found' : 'Not found',
                fixBtn: fixBtn ? 'Found' : 'Not found',
                exportBtn: exportBtn ? 'Found' : 'Not found'
            });
        };
        
        function checkBackendStatus() {
            fetch('http://localhost:8002/health')
                .then(response => response.json())
                .then(data => {
                    const statusElement = document.getElementById('backendStatus');
                    if (data.status === 'ok') {
                        statusElement.textContent = '🟢 Online';
                        statusElement.className = 'status-online';
                    } else {
                        statusElement.textContent = '🔴 Offline';
                        statusElement.className = 'status-offline';
                    }
                })
                .catch(error => {
                    const statusElement = document.getElementById('backendStatus');
                    statusElement.textContent = '🔴 Offline';
                    statusElement.className = 'status-offline';
                });
        }
        
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
            
            // Display summary
            const totalFindings = data.findings.length;
            const activeFindings = data.findings.length; // All findings are active in our system
            const suppressedFindings = 0; // No suppression in current system
            const suppressionRate = 0; // No suppression in current system
            
            console.log('📈 Summary stats:', {totalFindings, activeFindings, suppressedFindings, suppressionRate});
            
            summaryDiv.innerHTML = `
                <h3>Scan Summary</h3>
                <div class="summary-stats">
                    <div class="stat">
                        <span class="stat-number">${totalFindings}</span>
                        <span class="stat-label">Total Findings</span>
                    </div>
                    <div class="stat">
                        <span class="stat-number">${activeFindings}</span>
                        <span class="stat-label">Active Issues</span>
                    </div>
                    <div class="stat">
                        <span class="stat-number">${suppressedFindings}</span>
                        <span class="stat-label">Suppressed</span>
                    </div>
                    <div class="stat">
                        <span class="stat-number">${suppressionRate}%</span>
                        <span class="stat-label">Suppression Rate</span>
                    </div>
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
                            <div class="finding-header">
                                <div class="finding-title">${finding.title}</div>
                                <span class="severity ${severityClass}">${finding.severity}</span>
                            </div>
                            <div class="finding-details">
                                <strong>CWE:</strong> ${finding.cwe_id}<br>
                                <strong>Line:</strong> ${finding.line}
                            </div>
                            <div class="finding-snippet">${finding.snippet}</div>
                        </div>
                    `;
                });
                findingsDiv.innerHTML += '</div>';
            }
            
            resultsDiv.style.display = 'block';
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
            fixedCodeContentDiv.innerHTML = escapeHtml(data.fixed_code);
            copyBtn.style.display = 'block';
            exportBtn.style.display = 'block';
        }
        
        function copyFixedCode() {
            try {
                const fixedCode = document.getElementById('fixedCodeContent').textContent;
                navigator.clipboard.writeText(fixedCode).then(() => {
                    showNotification('✅ Fixed code copied to clipboard!', 'success');
                }).catch(() => {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = fixedCode;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showNotification('✅ Fixed code copied to clipboard!', 'success');
                });
            } catch (error) {
                console.error('❌ Copy error:', error);
                showNotification('❌ Failed to copy code', 'error');
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
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
                    showNotification('❌ Please select a file first', 'error');
                    return;
                }
                
                // Check file extension
                const allowedExtensions = ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'];
                const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
                
                if (!allowedExtensions.includes(fileExtension)) {
                    showNotification('❌ Please select a valid C/C++ file (.c, .cpp, .h, .hpp, .cc, .cxx)', 'error');
                    return;
                }
                
                const reader = new FileReader();
                reader.onload = function(e) {
                    const content = e.target.result;
                    document.getElementById('code').value = content;
                    showNotification(`✅ File "${file.name}" loaded successfully!`, 'success');
                    console.log(`📁 File loaded: ${file.name} (${content.length} characters)`);
                };
                
                reader.onerror = function() {
                    showNotification('❌ Error reading file', 'error');
                };
                
                reader.readAsText(file);
                
            } catch (error) {
                console.error('❌ Load file error:', error);
                showNotification('❌ Error loading file: ' + error.message, 'error');
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
                showNotification('✅ Report exported successfully!', 'success');
            } catch (error) {
                console.error('❌ Export error:', error);
                showNotification('❌ Failed to export report', 'error');
            }
        }
        
        // Test function for debugging
        function testButtons() {
            console.log('🧪 Testing button functionality...');
            
            // Test scan button
            const scanBtn = document.querySelector('button[onclick="scanCode()"]');
            if (scanBtn) {
                console.log('✅ Scan button found');
                scanBtn.click();
            } else {
                console.log('❌ Scan button not found');
            }
            
            // Test clear button
            const clearBtn = document.querySelector('button[onclick="clearCode()"]');
            if (clearBtn) {
                console.log('✅ Clear button found');
            } else {
                console.log('❌ Clear button not found');
            }
            
            // Test fix button
            const fixBtn = document.getElementById('fixBtn');
            if (fixBtn) {
                console.log('✅ Fix button found');
            } else {
                console.log('❌ Fix button not found');
            }
        }
        
        // Notification system
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 12px 20px;
                border-radius: 8px;
                color: white;
                font-weight: 600;
                z-index: 10000;
                animation: slideIn 0.3s ease-out;
                max-width: 300px;
                word-wrap: break-word;
            `;
            
            // Set background color based on type
            switch(type) {
                case 'success':
                    notification.style.backgroundColor = '#00cc00';
                    break;
                case 'error':
                    notification.style.backgroundColor = '#ff4444';
                    break;
                case 'warning':
                    notification.style.backgroundColor = '#ff8800';
                    break;
                default:
                    notification.style.backgroundColor = '#333333';
            }
            
            document.body.appendChild(notification);
            
            // Auto remove after 3 seconds
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease-in';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
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
                    showNotification('⚠️ No vulnerabilities found to fix', 'warning');
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
        
        // Add CSS animations for notifications
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
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
