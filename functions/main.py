import os
import json
import requests
import openai
from firebase_functions import https_fn
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure OpenAI
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable is required")

# Initialize OpenAI client
try:
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"Error initializing OpenAI client: {e}")
    client = None

def mock_sast_scan(code):
    """Mock SAST scanner that identifies common C/C++ vulnerabilities"""
    findings = []
    
    # Check for buffer overflow vulnerabilities
    if 'strcpy(' in code and 'strlen(' in code:
        findings.append({
            "id": "v1",
            "cwe": "CWE-120",
            "title": "Buffer Overflow",
            "severity": "HIGH",
            "line_start": 1,
            "line_end": 1,
            "confidence": "high",
            "code_excerpt": "strcpy(buffer, user_input);",
            "evidence": "Unbounded string copy without size check",
            "fix_strategy": "Use strncpy with proper bounds checking",
            "status": "OPEN"
        })
    
    # Check for format string vulnerabilities
    if 'printf(' in code and not 'printf("%s"' in code:
        findings.append({
            "id": "v2", 
            "cwe": "CWE-134",
            "title": "Format String Vulnerability",
            "severity": "HIGH",
            "line_start": 1,
            "line_end": 1,
            "confidence": "high",
            "code_excerpt": "printf(user_input);",
            "evidence": "User-controlled format string",
            "fix_strategy": "Use literal format string: printf(\"%s\", user_input);",
            "status": "OPEN"
        })
    
    # Check for command injection
    if 'system(' in code:
        findings.append({
            "id": "v3",
            "cwe": "CWE-78", 
            "title": "Command Injection",
            "severity": "CRITICAL",
            "line_start": 1,
            "line_end": 1,
            "confidence": "high",
            "code_excerpt": "system(command);",
            "evidence": "Direct system() call with user input",
            "fix_strategy": "Use execve() or removing system() calls",
            "status": "OPEN"
        })
    
    return {
        "summary": {
            "status": "ok" if findings else "no_issues",
            "notes": f"Found {len(findings)} potential vulnerabilities"
        },
        "vulnerabilities": findings
    }

def call_gpt_for_fix(code, findings):
    """Call GPT API to fix vulnerabilities"""
    if not client:
        return {"error": "OpenAI client not available"}
    
    try:
        # Create a detailed prompt for GPT
        findings_text = "\n".join([
            f"- {f['title']} (CWE-{f['cwe'].split('-')[1]}): {f['evidence']}"
            for f in findings
        ])
        
        prompt = f"""You are a senior secure-coding engineer for C (C11/POSIX). 

ORIGINAL CODE WITH VULNERABILITIES:
```c
{code}
```

VULNERABILITIES FOUND:
{findings_text}

Please provide a SECURE version of this code that fixes all the identified vulnerabilities. 

REQUIREMENTS:
1. Fix all buffer overflows (CWE-120) by using bounded functions like strncpy, snprintf
2. Fix format string vulnerabilities (CWE-134) by using literal format strings
3. Fix command injection (CWE-78) by using execve() or removing system() calls
4. Add proper bounds checking and error handling
5. Maintain the original functionality while making it secure
6. Include necessary headers and security best practices

Return ONLY the fixed C code, no explanations."""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
            temperature=0.1
        )
        
        fixed_code = response.choices[0].message.content.strip()
        
        # Clean up the response (remove markdown if present)
        if fixed_code.startswith("```c"):
            fixed_code = fixed_code[4:]
        if fixed_code.endswith("```"):
            fixed_code = fixed_code[:-3]
        fixed_code = fixed_code.strip()
        
        return {
            "fixed_code": fixed_code,
            "status": "success"
        }
        
    except Exception as e:
        print(f"Error calling GPT API: {e}")
        return {"error": f"Failed to call GPT API: {str(e)}"}

@https_fn.on_request()
def app(req: https_fn.Request) -> https_fn.Response:
    """Main Firebase Cloud Function that handles all API requests"""
    
    # Handle CORS
    if req.method == 'OPTIONS':
        return https_fn.Response(
            status=200,
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
            }
        )
    
    # Set CORS headers for all responses
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    }
    
    try:
        if req.method == 'GET':
            # Health check endpoint
            if req.path == '/api/health':
                return https_fn.Response(
                    json.dumps({"status": "healthy", "service": "SAFECode-Web API"}),
                    status=200,
                    headers=headers
                )
            else:
                return https_fn.Response(
                    json.dumps({"error": "Endpoint not found"}),
                    status=404,
                    headers=headers
                )
        
        elif req.method == 'POST':
            if req.path == '/api/scan':
                # Scan endpoint
                data = req.get_json()
                if not data or 'code' not in data:
                    return https_fn.Response(
                        json.dumps({"error": "Code is required"}),
                        status=400,
                        headers=headers
                    )
                
                code = data['code']
                findings = mock_sast_scan(code)
                
                return https_fn.Response(
                    json.dumps(findings),
                    status=200,
                    headers=headers
                )
            
            elif req.path == '/api/fix':
                # Fix endpoint
                data = req.get_json()
                if not data or 'code' not in data or 'findings' not in data:
                    return https_fn.Response(
                        json.dumps({"error": "Code and findings are required"}),
                        status=400,
                        headers=headers
                    )
                
                code = data['code']
                findings = data['findings']
                
                result = call_gpt_for_fix(code, findings)
                
                return https_fn.Response(
                    json.dumps(result),
                    status=200,
                    headers=headers
                )
            
            else:
                return https_fn.Response(
                    json.dumps({"error": "Endpoint not found"}),
                    status=404,
                    headers=headers
                )
        
        else:
            return https_fn.Response(
                json.dumps({"error": "Method not allowed"}),
                status=405,
                headers=headers
            )
    
    except Exception as e:
        print(f"Error in app function: {e}")
        return https_fn.Response(
            json.dumps({"error": f"Internal server error: {str(e)}"}),
            status=500,
            headers=headers
        )
