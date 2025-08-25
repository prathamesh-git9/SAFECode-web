const express = require('express');
const cors = require('cors');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = '2.1.0'; // Updated version for GPT integration

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// GPT API Key - use environment variable only
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Scan endpoint
app.post('/api/scan', async (req, res) => {
    try {
        const { code } = req.body;

        console.log(`[${VERSION}] Received scan request with code:`, code ? code.substring(0, 100) + '...' : 'No code');

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        // Mock SAST scanner that identifies common C/C++ vulnerabilities
        const findings = [];

        // Check for buffer overflow vulnerabilities (strcpy)
        if (code.includes('strcpy(') && !code.includes('strncpy(')) {
            findings.push({
                id: "v1",
                cwe: "CWE-120",
                title: "Buffer Overflow",
                severity: "HIGH",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "strcpy(buffer, user_input);",
                evidence: "Unbounded string copy without size check",
                fix_strategy: "Use strncpy with proper bounds checking",
                status: "OPEN"
            });
        }

        // Check for format string vulnerabilities (printf without format string)
        if (code.includes('printf(') && !code.includes('printf("%s"') && !code.includes('printf("%d"') && !code.includes('printf("%f"') && !code.includes('printf("\\n"')) {
            findings.push({
                id: "v2",
                cwe: "CWE-134",
                title: "Format String Vulnerability",
                severity: "HIGH",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "printf(user_input);",
                evidence: "User-controlled format string",
                fix_strategy: "Use literal format string: printf(\"%s\", user_input);",
                status: "OPEN"
            });
        }

        // Check for command injection (system calls)
        if (code.includes('system(') && !code.includes('// system(')) {
            findings.push({
                id: "v3",
                cwe: "CWE-78",
                title: "Command Injection",
                severity: "CRITICAL",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "system(command);",
                evidence: "Direct system() call with user input",
                fix_strategy: "Use execve() with validated arguments or avoid shell",
                status: "OPEN"
            });
        }

        // Check for gets() function (deprecated and dangerous)
        if (code.includes('gets(') && !code.includes('fgets(')) {
            findings.push({
                id: "v4",
                cwe: "CWE-120",
                title: "Buffer Overflow (gets)",
                severity: "CRITICAL",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "gets(buffer);",
                evidence: "gets() function is inherently unsafe",
                fix_strategy: "Replace gets() with fgets() or scanf() with proper bounds",
                status: "OPEN"
            });
        }

        // Check for sprintf without bounds
        if (code.includes('sprintf(') && !code.includes('snprintf(')) {
            findings.push({
                id: "v5",
                cwe: "CWE-120",
                title: "Buffer Overflow (sprintf)",
                severity: "HIGH",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "sprintf(buffer, format, ...);",
                evidence: "sprintf() without bounds checking",
                fix_strategy: "Use snprintf() with proper buffer size",
                status: "OPEN"
            });
        }

        // Check for strcat without bounds
        if (code.includes('strcat(') && !code.includes('strncat(')) {
            findings.push({
                id: "v6",
                cwe: "CWE-120",
                title: "Buffer Overflow (strcat)",
                severity: "HIGH",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "strcat(buffer, string);",
                evidence: "strcat() without bounds checking",
                fix_strategy: "Use strncat() with proper buffer size",
                status: "OPEN"
            });
        }

        // Check for scanf without bounds
        if (code.includes('scanf(') && !code.includes('scanf("%s"') && !code.includes('scanf("%d"') && !code.includes('fgets(')) {
            findings.push({
                id: "v7",
                cwe: "CWE-120",
                title: "Buffer Overflow (scanf)",
                severity: "HIGH",
                line_start: 1,
                line_end: 1,
                confidence: "high",
                code_excerpt: "scanf(format, buffer);",
                evidence: "scanf() without bounds checking",
                fix_strategy: "Use scanf() with proper format specifiers or fgets()",
                status: "OPEN"
            });
        }

        const result = {
            summary: {
                status: findings.length > 0 ? "ok" : "no_issues",
                notes: findings.length > 0 ? `Found ${findings.length} potential vulnerabilities` : "No vulnerabilities detected"
            },
            vulnerabilities: findings
        };

        console.log(`[${VERSION}] Scan result:`, result);
        res.status(200).json(result);

    } catch (error) {
        console.error(`[${VERSION}] Scan error:`, error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// Fix endpoint with hybrid GPT + pattern-based approach
app.post('/api/fix', async (req, res) => {
    try {
        const { code, findings } = req.body;

        console.log(`[${VERSION}] Received fix request with ${findings ? findings.length : 0} findings`);

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        if (!findings || findings.length === 0) {
            return res.status(400).json({ error: 'No vulnerabilities to fix' });
        }

        let fixedCode = code;
        let fixMethod = 'pattern-based';

        // Try GPT API first for complex fixes
        if (OPENAI_API_KEY) {
            try {
                console.log(`[${VERSION}] Attempting GPT fix...`);
                
                const gptResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
                    model: 'gpt-3.5-turbo',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a security expert who fixes C code vulnerabilities. Return only the fixed code without explanations.'
                        },
                        {
                            role: 'user',
                            content: `Fix these vulnerabilities in the following C code:\n\n${code}\n\nVulnerabilities found:\n${findings.map(f => `- ${f.title}: ${f.evidence}`).join('\n')}`
                        }
                    ],
                    max_tokens: 2000,
                    temperature: 0.1
                }, {
                    headers: {
                        'Authorization': `Bearer ${OPENAI_API_KEY}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 15000
                });

                if (gptResponse.data.choices && gptResponse.data.choices[0]) {
                    fixedCode = gptResponse.data.choices[0].message.content;
                    fixMethod = 'gpt';
                    console.log(`[${VERSION}] GPT fix applied successfully`);
                }
            } catch (gptError) {
                console.log(`[${VERSION}] GPT fix failed, falling back to pattern-based:`, gptError.message);
            }
        }

        // Fallback to pattern-based fixes if GPT fails or is not available
        if (fixMethod === 'pattern-based') {
            // Apply fixes in a specific order to prevent conflicts

            // 1. Fix system calls first (comment them out)
            fixedCode = fixedCode.replace(/system\s*\(\s*([^)]+)\s*\)/g,
                '// system($1); // SECURITY: Removed for safety');

            // 2. Fix gets function - only match gets(), not fgets()
            fixedCode = fixedCode.replace(/\bgets\s*\(\s*([^)]+)\s*\)/g,
                'fgets($1, sizeof($1), stdin)');

            // 3. Fix strcpy
            fixedCode = fixedCode.replace(/strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
                'strncpy($1, $2, sizeof($1) - 1);\n    $1[sizeof($1) - 1] = \'\\0\'');

            // 4. Fix sprintf - correct parameter order
            fixedCode = fixedCode.replace(/sprintf\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
                'snprintf($1, sizeof($1), $2)');

            // 5. Fix strcat
            fixedCode = fixedCode.replace(/strcat\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
                'strncat($1, $2, sizeof($1) - strlen($1) - 1)');

            // 6. Fix scanf
            fixedCode = fixedCode.replace(/scanf\s*\(\s*"%s"\s*,\s*([^)]+)\s*\)/g,
                'fgets($1, sizeof($1), stdin)');

            // 7. Fix printf format string (only if not already fixed)
            fixedCode = fixedCode.replace(/printf\s*\(\s*([^)]+)\s*\)/g, (match, arg) => {
                // Skip if it's already a format string or if it's a comment
                if (arg.includes('"%s"') || arg.includes('"%d"') || arg.includes('"%f"') ||
                    arg.includes('//') || arg.includes('/*')) {
                    return match;
                }
                return `printf("%s", ${arg})`;
            });

            // Clean up any double comments that might have been created
            fixedCode = fixedCode.replace(/\/\/ \/\/ /g, '// ');
            fixedCode = fixedCode.replace(/\/\/ SECURITY: Removed for safety; \/\/ SECURITY: Removed for safety/g,
                '// SECURITY: Removed for safety');

            // Add security headers and includes if not present
            if (!fixedCode.includes('#include <string.h>')) {
                fixedCode = fixedCode.replace('#include <stdio.h>', '#include <stdio.h>\n#include <string.h>');
            }

            // Add security best practices
            if (!fixedCode.includes('// Security best practices')) {
                fixedCode = fixedCode.replace(
                    'int main() {',
                    `int main() {
    // Security best practices applied:
    // - Bounded string operations
    // - Format string protection
    // - Command injection prevention`
                );
            }
        }

        console.log(`[${VERSION}] Fix applied successfully using ${fixMethod} method`);
        res.status(200).json({
            fixed_code: fixedCode,
            status: 'success',
            fixes_applied: findings.length,
            fix_method: fixMethod,
            version: VERSION
        });

    } catch (error) {
        console.error(`[${VERSION}] Fix error:`, error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'SAFECode API is running', 
        version: VERSION,
        gpt_available: !!OPENAI_API_KEY
    });
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 SAFECode Web Server v${VERSION} running on http://localhost:${PORT}`);
    console.log(`📡 API endpoints:`);
    console.log(`   - POST /api/scan - Scan code for vulnerabilities`);
    console.log(`   - POST /api/fix - Fix vulnerabilities in code`);
    console.log(`   - GET /api/health - Health check`);
    console.log(`🤖 GPT API: ${OPENAI_API_KEY ? 'Available' : 'Not configured'}`);
});
