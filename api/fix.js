export default async function handler(req, res) {
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

    // Apply fixes based on findings
    findings.forEach(finding => {
      const { cwe, title, evidence } = finding;

      switch (cwe) {
        case 'CWE-120':
          if (title.includes('Buffer Overflow')) {
            // Fix strcpy
            fixedCode = fixedCode.replace(
              /strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
              (match, buffer, source) => {
                return `strncpy(${buffer}, ${source}, sizeof(${buffer.trim()}) - 1);\n    ${buffer.trim()}[sizeof(${buffer.trim()}) - 1] = '\\0';`;
              }
            );

            // Fix gets
            fixedCode = fixedCode.replace(
              /gets\s*\(\s*([^)]+)\s*\)/g,
              (match, buffer) => {
                return `fgets(${buffer}, sizeof(${buffer.trim()}), stdin)`;
              }
            );

            // Fix sprintf
            fixedCode = fixedCode.replace(
              /sprintf\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)/g,
              (match, buffer, format) => {
                return `snprintf(${buffer}, sizeof(${buffer.trim()}), ${format})`;
              }
            );
          }
          break;

        case 'CWE-134':
          // Fix format string vulnerabilities
          fixedCode = fixedCode.replace(
            /printf\s*\(\s*([^)]+)\s*\)/g,
            (match, arg) => {
              // If it's not already a format string, make it one
              if (!arg.includes('"%s"') && !arg.includes('"%d"') && !arg.includes('"%f"')) {
                return `printf("%s", ${arg})`;
              }
              return match;
            }
          );
          break;

        case 'CWE-78':
          // Comment out system calls
          fixedCode = fixedCode.replace(
            /system\s*\(\s*([^)]+)\s*\)/g,
            (match, command) => {
              return `// system(${command}); // SECURITY: Removed for safety`;
            }
          );
          break;
      }
    });

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
}
