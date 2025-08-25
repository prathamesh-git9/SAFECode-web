// Import Firebase auth
import { auth, provider } from './firebase-config.js';

// Theme management
let currentTheme = localStorage.getItem('theme') || 'light';

// Authentication state
let currentUser = null;

// Initialize theme and authentication
document.addEventListener('DOMContentLoaded', function () {
    setTheme(currentTheme);
    setupKeyboardShortcuts();
    initializeAuth();
});

// Firebase Authentication Functions
function initializeAuth() {
    // Listen for auth state changes
    import('firebase/auth').then(({ onAuthStateChanged }) => {
        onAuthStateChanged(auth, function (user) {
            if (user) {
                // User is signed in
                currentUser = user;
                updateAuthUI(true);
                showNotification(`Welcome, ${user.displayName}!`, 'success');
            } else {
                // User is signed out
                currentUser = null;
                updateAuthUI(false);
            }
        });
    });
}

function updateAuthUI(isSignedIn) {
    const authButtons = document.getElementById('authButtons');
    const userProfile = document.getElementById('userProfile');
    const userName = document.getElementById('userName');

    if (isSignedIn && currentUser) {
        authButtons.style.display = 'none';
        userProfile.style.display = 'flex';
        userName.textContent = currentUser.displayName || currentUser.email;
    } else {
        authButtons.style.display = 'flex';
        userProfile.style.display = 'none';
    }
}

function signInWithGoogle() {
    import('firebase/auth').then(({ signInWithPopup }) => {
        signInWithPopup(auth, provider)
            .then((result) => {
                // Successfully signed in
                console.log('Signed in successfully');
            })
            .catch((error) => {
                console.error('Sign-in error:', error);
                showNotification('Sign-in failed. Please try again.', 'error');
            });
    });
}

function signOut() {
    import('firebase/auth').then(({ signOut: firebaseSignOut }) => {
        firebaseSignOut(auth)
            .then(() => {
                showNotification('Signed out successfully', 'info');
            })
            .catch((error) => {
                console.error('Sign-out error:', error);
                showNotification('Sign-out failed. Please try again.', 'error');
            });
    });
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
    localStorage.setItem('theme', theme);
    currentTheme = theme;
}

function toggleTheme() {
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
}

// API endpoints for Vercel serverless functions
const API_BASE = window.location.origin + '/api';

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;

    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

function setLoading(element, loading) {
    if (loading) {
        element.classList.add('loading');
        element.disabled = true;
    } else {
        element.classList.remove('loading');
        element.disabled = false;
    }
}

// File handling
function loadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.match(/\.(c|cpp|h|hpp)$/i)) {
        showNotification('Please select a C/C++ file (.c, .cpp, .h, .hpp)', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
        document.getElementById('codeInput').value = e.target.result;
        showNotification(`Loaded file: ${file.name}`, 'success');
    };
    reader.readAsText(file);
}

function clearCode() {
    document.getElementById('codeInput').value = '';
    document.getElementById('fileInput').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('fixedCodeSection').style.display = 'none';
    showNotification('Code cleared', 'info');
}

// API calls
async function scanCode() {
    const codeInput = document.getElementById('codeInput');
    const code = codeInput.value.trim();

    if (!code) {
        showNotification('Please enter some code to scan', 'error');
        return;
    }

    const scanBtn = document.querySelector('.btn-primary');
    setLoading(scanBtn, true);

    try {
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        displayResults(data);

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            document.getElementById('fixBtn').style.display = 'inline-flex';
            showNotification(`Found ${data.vulnerabilities.length} vulnerabilities`, 'info');
        } else {
            document.getElementById('fixBtn').style.display = 'none';
            showNotification('No vulnerabilities found!', 'success');
        }

    } catch (error) {
        console.error('Scan error:', error);
        showNotification('Failed to scan code. Please try again.', 'error');
    } finally {
        setLoading(scanBtn, false);
    }
}

async function fixCode() {
    const codeInput = document.getElementById('codeInput');
    const code = codeInput.value.trim();
    const resultsSection = document.getElementById('resultsSection');

    if (!code) {
        showNotification('Please enter some code to fix', 'error');
        return;
    }

    // Get vulnerabilities from the displayed results
    const vulnerabilityCards = document.querySelectorAll('.vulnerability-card');
    const findings = [];

    vulnerabilityCards.forEach(card => {
        const title = card.querySelector('.vulnerability-title').textContent;
        const cwe = card.querySelector('.vulnerability-cwe').textContent;
        const evidence = card.querySelector('.vulnerability-evidence').textContent;

        findings.push({
            title: title,
            cwe: cwe,
            evidence: evidence
        });
    });

    if (findings.length === 0) {
        showNotification('No vulnerabilities to fix', 'info');
        return;
    }

    const fixBtn = document.getElementById('fixBtn');
    setLoading(fixBtn, true);

    try {
        const response = await fetch(`${API_BASE}/fix`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                code: code,
                findings: findings
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        displayFixedCode(data.fixed_code);
        showNotification('Code fixed successfully!', 'success');

    } catch (error) {
        console.error('Fix error:', error);
        showNotification('Failed to fix code. Please try again.', 'error');
    } finally {
        setLoading(fixBtn, false);
    }
}

// Display functions
function displayResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    const vulnerabilitiesGrid = document.getElementById('vulnerabilitiesGrid');

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        vulnerabilitiesGrid.innerHTML = `
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <div>
                        <div class="vulnerability-title">No Vulnerabilities Found</div>
                        <div class="vulnerability-cwe">Clean Code</div>
                    </div>
                    <span class="severity-badge severity-low">Safe</span>
                </div>
                <div class="vulnerability-evidence">
                    Your code appears to be secure! No common vulnerabilities were detected.
                </div>
            </div>
        `;
    } else {
        vulnerabilitiesGrid.innerHTML = data.vulnerabilities.map(vuln => `
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <div>
                        <div class="vulnerability-title">${vuln.title}</div>
                        <div class="vulnerability-cwe">${vuln.cwe}</div>
                    </div>
                    <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <div class="vulnerability-evidence">${vuln.evidence}</div>
                ${vuln.code_excerpt ? `<div class="vulnerability-code">${vuln.code_excerpt}</div>` : ''}
            </div>
        `).join('');
    }

    resultsSection.style.display = 'block';
}

function displayFixedCode(fixedCode) {
    const fixedCodeSection = document.getElementById('fixedCodeSection');
    const fixedCodeElement = document.getElementById('fixedCode');

    fixedCodeElement.textContent = fixedCode;
    fixedCodeSection.style.display = 'block';

    // Scroll to fixed code section
    fixedCodeSection.scrollIntoView({ behavior: 'smooth' });
}

// Copy functionality
function copyFixedCode() {
    const fixedCode = document.getElementById('fixedCode').textContent;

    if (!fixedCode) {
        showNotification('No fixed code to copy', 'error');
        return;
    }

    navigator.clipboard.writeText(fixedCode).then(() => {
        showNotification('Fixed code copied to clipboard!', 'success');
    }).catch(() => {
        showNotification('Failed to copy code', 'error');
    });
}

// Export functionality
function exportReport() {
    const codeInput = document.getElementById('codeInput').value;
    const resultsSection = document.getElementById('resultsSection');
    const fixedCodeSection = document.getElementById('fixedCodeSection');

    if (!codeInput.trim()) {
        showNotification('No code to export', 'error');
        return;
    }

    let report = `SAFECode Security Analysis Report\n`;
    report += `Generated on: ${new Date().toLocaleString()}\n\n`;

    report += `ORIGINAL CODE:\n`;
    report += `${codeInput}\n\n`;

    if (resultsSection.style.display !== 'none') {
        const vulnerabilities = document.querySelectorAll('.vulnerability-card');
        if (vulnerabilities.length > 0) {
            report += `VULNERABILITIES FOUND:\n`;
            vulnerabilities.forEach((vuln, index) => {
                const title = vuln.querySelector('.vulnerability-title').textContent;
                const cwe = vuln.querySelector('.vulnerability-cwe').textContent;
                const severity = vuln.querySelector('.severity-badge').textContent;
                const evidence = vuln.querySelector('.vulnerability-evidence').textContent;

                report += `${index + 1}. ${title} (${cwe}) - ${severity}\n`;
                report += `   Evidence: ${evidence}\n\n`;
            });
        }
    }

    if (fixedCodeSection.style.display !== 'none') {
        const fixedCode = document.getElementById('fixedCode').textContent;
        report += `FIXED CODE:\n`;
        report += `${fixedCode}\n`;
    }

    // Create and download file
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `safecode-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification('Report exported successfully!', 'success');
}

// Keyboard shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function (e) {
        // Ctrl+Enter: Scan code
        if (e.ctrlKey && e.key === 'Enter') {
            e.preventDefault();
            scanCode();
        }

        // Ctrl+Shift+F: Fix code
        if (e.ctrlKey && e.shiftKey && e.key === 'F') {
            e.preventDefault();
            fixCode();
        }

        // Ctrl+K: Clear code
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            clearCode();
        }

        // Ctrl+O: Open file
        if (e.ctrlKey && e.key === 'o') {
            e.preventDefault();
            document.getElementById('fileInput').click();
        }
    });
}

// Auto-resize textarea
document.addEventListener('DOMContentLoaded', function () {
    const textarea = document.getElementById('codeInput');
    if (textarea) {
        textarea.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = Math.max(300, this.scrollHeight) + 'px';
        });
    }
});
