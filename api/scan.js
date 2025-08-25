module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { code } = req.body;

        console.log('Received scan request with code:', code.substring(0, 100) + '...');

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        // Mock SAST scanner that identifies common C/C++ vulnerabilities
        const findings = [];

        // Check for buffer overflow vulnerabilities
        if (code.includes('strcpy(')) {
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

        // Check for format string vulnerabilities
        if (code.includes('printf(') && !code.includes('printf("%s"') && !code.includes('printf("%d"') && !code.includes('printf("%f"')) {
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

        // Check for command injection
        if (code.includes('system(')) {
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
        if (code.includes('gets(')) {
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
        if (code.includes('scanf(') && !code.includes('scanf("%s"') && !code.includes('scanf("%d"')) {
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

        console.log('Scan result:', result);
        res.status(200).json(result);

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
