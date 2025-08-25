#!/usr/bin/env python3
"""
Test the auto-fix system with complex vulnerable code
"""

import requests
import openai
import os

# GPT Configuration
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
GPT_MODEL = "gpt-4o-mini"
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

def test_complex_vulnerabilities():
    """Test with complex vulnerable code containing multiple issues."""
    
    # Complex vulnerable code with multiple issues
    complex_vulnerable_code = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_SIZE 100

void vulnerable_function(char *input) {
    char buffer[50];
    char command[200];
    
    // Multiple buffer overflow vulnerabilities
    strcpy(buffer, input);  // CWE-120: Buffer overflow
    strcat(buffer, " - dangerous");  // CWE-120: Buffer overflow
    
    // Format string vulnerability
    printf(buffer);  // CWE-134: Format string
    
    // Command injection vulnerabilities
    sprintf(command, "ls -la %s", input);  // CWE-78: Command injection
    system(command);  // CWE-78: Command injection
    
    // Integer overflow
    int size = strlen(input) * 2;  // CWE-190: Integer overflow
    char *dynamic_buffer = malloc(size);
    
    // Use after free
    free(dynamic_buffer);
    strcpy(dynamic_buffer, "use after free");  // CWE-416: Use after free
    
    // Null pointer dereference
    char *ptr = NULL;
    if (input[0] == 'A') {
        ptr = malloc(10);
    }
    strcpy(ptr, "null deref");  // CWE-476: Null pointer dereference
}

int main(int argc, char *argv[]) {
    char user_input[MAX_SIZE];
    
    // Unsafe input function
    gets(user_input);  // CWE-120: Buffer overflow
    
    // Multiple vulnerabilities in one function
    vulnerable_function(user_input);
    
    // Stack-based buffer overflow
    char small_buffer[10];
    strcpy(small_buffer, "This is a very long string that will definitely overflow the buffer");
    
    // Format string with user input
    char format_string[100];
    sprintf(format_string, "User said: %s", user_input);
    printf(format_string);  // CWE-134: Format string
    
    // Command injection with user input
    char system_command[300];
    sprintf(system_command, "echo 'User input: %s'", user_input);
    system(system_command);  // CWE-78: Command injection
    
    // Integer overflow in array access
    int index = strlen(user_input) * 2;
    char array[100];
    array[index] = 'X';  // CWE-190: Integer overflow leading to buffer overflow
    
    return 0;
}"""
    
    print("🧪 Testing Complex Vulnerabilities")
    print("=" * 60)
    print("\n📝 Complex Vulnerable Code:")
    print("-" * 40)
    print(complex_vulnerable_code)
    print("-" * 40)
    
    # Test 1: Backend auto-fix
    print("\n🔍 Test 1: Backend Auto-Fix")
    print("=" * 40)
    
    try:
        # Scan for vulnerabilities
        response = requests.post('http://localhost:8002/scan', 
                                json={'filename': 'complex_test.c', 'code': complex_vulnerable_code})
        
        if response.status_code == 200:
            result = response.json()
            findings = result.get('findings', [])
            print(f"✅ Found {len(findings)} vulnerabilities:")
            
            for i, finding in enumerate(findings, 1):
                print(f"   {i}. {finding['title']} (Line {finding['line']}) - {finding['severity']}")
            
            # Auto-fix with backend
            fix_response = requests.post('http://localhost:8002/fix', 
                                        json={
                                            'filename': 'complex_test.c', 
                                            'code': complex_vulnerable_code,
                                            'findings': findings
                                        })
            
            if fix_response.status_code == 200:
                fix_result = fix_response.json()
                backend_fixed_code = fix_result.get('fixed_code', 'No fixed code')
                
                print(f"\n✅ Backend fix completed")
                print(f"📏 Fixed code length: {len(backend_fixed_code)} characters")
                
                print("\n🟢 Backend Fixed Code:")
                print("-" * 40)
                print(backend_fixed_code)
                print("-" * 40)
                
            else:
                print(f"❌ Backend fix failed: {fix_response.text}")
        else:
            print(f"❌ Backend scan failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Backend test error: {e}")
    
    # Test 2: Direct GPT fix
    print("\n🤖 Test 2: Direct GPT Fix")
    print("=" * 40)
    
    try:
        # Prepare the prompt for complex vulnerabilities
        prompt = f"""You are a security expert C programmer. Fix the following complex C code by addressing ALL security vulnerabilities detected.

ORIGINAL CODE:
{complex_vulnerable_code}

DETECTED VULNERABILITIES:
- Multiple Buffer Overflow vulnerabilities (CWE-120)
- Format String vulnerabilities (CWE-134) 
- Command Injection vulnerabilities (CWE-78)
- Integer Overflow vulnerabilities (CWE-190)
- Use After Free vulnerabilities (CWE-416)
- Null Pointer Dereference vulnerabilities (CWE-476)

INSTRUCTIONS:
1. Fix ALL vulnerabilities while maintaining the original functionality
2. Use secure alternatives (strncpy, snprintf, fgets, etc.)
3. Add proper bounds checking and null termination
4. Handle memory management safely
5. Add proper error handling
6. Keep the code readable and well-commented
7. Return ONLY the fixed C code, no explanations

FIXED CODE:"""
        
        # Call GPT API
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[
                {"role": "system", "content": "You are a security expert C programmer. Provide only the fixed code without explanations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=3000
        )
        
        gpt_fixed_code = response.choices[0].message.content.strip()
        
        # Clean up the response
        if gpt_fixed_code.startswith("```c"):
            gpt_fixed_code = gpt_fixed_code[3:]
        if gpt_fixed_code.startswith("```"):
            gpt_fixed_code = gpt_fixed_code[3:]
        if gpt_fixed_code.endswith("```"):
            gpt_fixed_code = gpt_fixed_code[:-3]
        gpt_fixed_code = gpt_fixed_code.strip()
        
        print("✅ GPT fix completed")
        print(f"📏 Fixed code length: {len(gpt_fixed_code)} characters")
        
        print("\n🟢 GPT Fixed Code:")
        print("-" * 40)
        print(gpt_fixed_code)
        print("-" * 40)
        
    except Exception as e:
        print(f"❌ GPT test error: {e}")
        gpt_fixed_code = None
    
    # Test 3: Simple but tricky vulnerability
    print("\n🎯 Test 3: Simple but Tricky Vulnerability")
    print("=" * 40)
    
    simple_tricky_code = """#include <stdio.h>
#include <string.h>

int main() {
    char buffer[5];
    char *user_input = "Hello World!";
    
    // This looks safe but isn't - missing size parameter
    strncpy(buffer, user_input, 5);
    // Missing null termination!
    
    // This will crash - buffer is not null-terminated
    printf("Buffer: %s\\n", buffer);
    
    return 0;
}"""
    
    print("\n📝 Simple Tricky Code:")
    print("-" * 40)
    print(simple_tricky_code)
    print("-" * 40)
    
    try:
        # Test with backend
        response = requests.post('http://localhost:8002/scan', 
                                json={'filename': 'tricky.c', 'code': simple_tricky_code})
        
        if response.status_code == 200:
            result = response.json()
            findings = result.get('findings', [])
            print(f"✅ Found {len(findings)} vulnerabilities in tricky code")
            
            for finding in findings:
                print(f"   • {finding['title']} (Line {finding['line']})")
            
            # Auto-fix
            fix_response = requests.post('http://localhost:8002/fix', 
                                        json={
                                            'filename': 'tricky.c', 
                                            'code': simple_tricky_code,
                                            'findings': findings
                                        })
            
            if fix_response.status_code == 200:
                fix_result = fix_response.json()
                tricky_fixed_code = fix_result.get('fixed_code', 'No fixed code')
                
                print(f"\n✅ Tricky code fix completed")
                print(f"📏 Fixed code length: {len(tricky_fixed_code)} characters")
                
                print("\n🟢 Tricky Code Fixed:")
                print("-" * 40)
                print(tricky_fixed_code)
                print("-" * 40)
                
        else:
            print(f"❌ Tricky code scan failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Tricky code test error: {e}")

def main():
    """Main test function."""
    print("🧪 Comprehensive Vulnerability Testing")
    print("=" * 60)
    
    test_complex_vulnerabilities()
    
    print("\n" + "=" * 60)
    print("🎯 Test Summary:")
    print("   • Tested complex code with multiple vulnerability types")
    print("   • Tested simple but tricky vulnerabilities")
    print("   • Compared backend vs GPT fixes")
    print("   • Web interface available at http://localhost:5000")

if __name__ == "__main__":
    main()
