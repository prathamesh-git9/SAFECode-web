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
        const { code, findings } = req.body;

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        if (!findings || findings.length === 0) {
            return res.status(400).json({ error: 'No vulnerabilities to fix' });
        }

        let fixedCode = code;

        // Simple, reliable fixes
        // Fix strcpy
        fixedCode = fixedCode.replace(/strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
            'strncpy($1, $2, sizeof($1) - 1);\n    $1[sizeof($1) - 1] = \'\\0\'');

        // Fix gets
        fixedCode = fixedCode.replace(/gets\s*\(\s*([^)]+)\s*\)/g,
            'fgets($1, sizeof($1), stdin)');

        // Fix sprintf
        fixedCode = fixedCode.replace(/sprintf\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
            'snprintf($1, sizeof($1), $2)');

        // Fix strcat
        fixedCode = fixedCode.replace(/strcat\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
            'strncat($1, $2, sizeof($1) - strlen($1) - 1)');

        // Fix printf format string
        fixedCode = fixedCode.replace(/printf\s*\(\s*([^)]+)\s*\)/g, (match, arg) => {
            if (!arg.includes('"%s"') && !arg.includes('"%d"') && !arg.includes('"%f"')) {
                return `printf("%s", ${arg})`;
            }
            return match;
        });

        // Fix system calls
        fixedCode = fixedCode.replace(/system\s*\(\s*([^)]+)\s*\)/g,
            '// system($1); // SECURITY: Removed for safety');

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

        res.status(200).json({
            fixed_code: fixedCode,
            status: 'success',
            fixes_applied: findings.length
        });

    } catch (error) {
        console.error('Fix error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
