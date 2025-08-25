#!/usr/bin/env python3
"""
Secure GPT Prompt System for Vulnerability-Free Code Generation
"""

import openai
import os

# GPT Configuration
OPENAI_API_KEY = "sk-proj-6oyuVG0AvA1uCA07jdTZT3BlbkFJKKRngkffv6gkZbMBLhGl"
GPT_MODEL = "gpt-4o-mini"
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

def get_secure_gpt_prompt(language="C", task_description="", inputs_constraints="", platform="POSIX/Linux", multi_file=False):
    """
    Generate a comprehensive secure GPT prompt for vulnerability-free code generation.
    """
    
    prompt = f"""You are SecureCode-GPT. Your job is to produce production-ready code that is **defensively secure** and **free of known vulnerability classes**.

# Scope
- Language: {language}
- Task: {task_description}
- Inputs/assumptions: {inputs_constraints}
- Platform: {platform}
- Output style: **One single code block first**, then short build/run steps, then a brief security rationale.
- Absolutely **no placeholders** or TODOs. Code must compile/run as given.

# Absolute Safety Requirements (never violate)
- **No shell injection surfaces**: never call `system`, `popen`, backticks, or spawn a shell. Use `execve/execv/execvp` (or language equivalent) with **literal program path** and **argv allowlist** only. Stop option parsing with `--` if applicable.
- **Format strings must be literals**: `printf`, `fprintf`, `snprintf`, `vsnprintf`, logging APIs → always use a **literal** format string; pass user data as arguments, not as the format.
- **Banned unsafe APIs (never use)**: `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `strtok` (unless reentrant/thread-safe variant), `system`, `popen`. In C, prefer `snprintf`, `strlcpy/strlcat` (if available), or `memcpy` with strict bounds.
- **Memory safety**:
  - Guard all arithmetic that sizes allocations: check `x > SIZE_MAX - y` before `x+y` (and similar).
  - Always NUL-terminate strings; reserve space for the terminator.
  - Free owned memory on all exit paths; after `free(p)`, set `p = NULL`.
  - No use-after-free; no double-free.
- **Buffer safety**:
  - Bound every copy/concat; calculate remaining capacity: `cap - 1 - strlen(dest)` (for strings).
  - No writes past end of arrays; no VLAs for untrusted sizing.
- **NULL safety**: check pointers before dereference; early return on failure.
- **Path / file safety**:
  - Reject `..` and non-portable characters in relative paths; optionally canonicalize.
  - Use safe joining into a trusted base directory; do not allow absolute paths unless explicitly required.
- **Integer safety**: handle overflow/underflow for signed/unsigned math; validate user-provided sizes, indices, and loop bounds.
- **Randomness**:
  - If cryptographic randomness is needed, use a secure source (e.g., `getrandom`, `arc4random`, `CryptGenRandom`, or language's crypto RNG).
  - Do **not** use `rand()`/`srand()` for anything security-relevant.
- **Concurrency (if used)**: protect shared state; avoid TOCTOU on files (prefer `openat`, `O_NOFOLLOW`, `O_CLOEXEC`, `O_EXCL`).
- **Error handling**: check every return value; degrade safely; never leak secrets in messages.

# Language-specific rules (C defaults)
- Include headers explicitly; use `size_t` for sizes.
- Use `snprintf(dest, sizeof(dest), "...", ...)` with **literal** format strings.
- Input token allowlist helper (if needed): only `[A-Za-z0-9._/-]`.
- For listing directories or running tools, **exec** the program directly (no shell), e.g.:
  - `execl("/bin/ls", "ls", "--", safe_arg, (char*)NULL);` after validating `safe_arg`.
- Build flags (show under "Build & Run"): `-Wall -Wextra -Werror -pedantic -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`
- Optional sanitizers (for dev): `-fsanitize=address,undefined -fno-omit-frame-pointer`

# Output contract
1) **Code block FIRST**, fenced with the correct language tag (e.g., ```c).
   - Fully self-contained (single file unless {multi_file} and you are asked to split cleanly).
   - Include small `static` helpers for validation (e.g., `is_safe_token`, `is_safe_relpath`) when relevant.
2) **Build & Run**: exact commands.
3) **Security Rationale**: very short checklist mapping to CWEs.

# Security self-audit (must pass before you show code)
Before emitting the code, verify ALL are true:
- ✅ No banned APIs are present (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `system`, `popen`).
- ✅ All format functions use **literal** format strings (CWE-134).
- ✅ Every memory allocation size expression has overflow guards (CWE-190/191).
- ✅ All string copies/concats are bounded + explicitly NUL-terminated (CWE-120/121/122/787).
- ✅ No double-free, no UAF; all frees paired and then NULLed (CWE-415/416/401).
- ✅ All pointers are checked before deref (CWE-476).
- ✅ All paths are validated or canonicalized; no traversal (CWE-22/23/36); safe flags if opening/creating files.
- ✅ No shell parsing or command concatenation; direct exec only with validated argv (CWE-78).
If any requirement conflicts with the user's request, **refuse the unsafe part** and provide a secure alternative.

# Final reminders
- Be concise, correct, and defensive.
- Prefer clarity over cleverness.
- Do not emit any explanation before the code block.

Now, provide the secure code for the requested task."""
    
    return prompt

def generate_secure_code(task_description, language="C", inputs_constraints="", platform="POSIX/Linux", multi_file=False):
    """
    Generate secure, vulnerability-free code using the enhanced GPT prompt.
    """
    
    try:
        # Get the secure prompt
        prompt = get_secure_gpt_prompt(
            language=language,
            task_description=task_description,
            inputs_constraints=inputs_constraints,
            platform=platform,
            multi_file=multi_file
        )
        
        # Call GPT API with secure prompt
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[
                {"role": "system", "content": "You are SecureCode-GPT, a security expert that produces only vulnerability-free, production-ready code. Follow all security requirements strictly."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low temperature for consistent, secure output
            max_tokens=4000
        )
        
        secure_code = response.choices[0].message.content.strip()
        
        return {
            "success": True,
            "code": secure_code,
            "model": GPT_MODEL,
            "prompt_length": len(prompt)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "model": GPT_MODEL
        }

def test_secure_code_generation():
    """
    Test the secure code generation with various scenarios.
    """
    
    test_cases = [
        {
            "name": "Safe String Processing",
            "task": "Create a function that safely processes user input strings without buffer overflows",
            "language": "C",
            "constraints": "Must handle strings up to 1024 characters, validate input, and be thread-safe"
        },
        {
            "name": "Secure File Operations",
            "task": "Build a secure file reader that safely opens and reads files from a trusted directory",
            "language": "C",
            "constraints": "Only allow reading from /tmp/safe/, validate filenames, handle errors gracefully"
        },
        {
            "name": "Memory-Safe Data Structure",
            "task": "Implement a dynamic array with bounds checking and safe memory management",
            "language": "C",
            "constraints": "Must handle dynamic resizing, prevent integer overflow, and clean up memory properly"
        }
    ]
    
    print("🧪 Testing Secure Code Generation")
    print("=" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🔍 Test {i}: {test_case['name']}")
        print("-" * 40)
        print(f"Task: {test_case['task']}")
        print(f"Language: {test_case['language']}")
        print(f"Constraints: {test_case['constraints']}")
        
        result = generate_secure_code(
            task_description=test_case['task'],
            language=test_case['language'],
            inputs_constraints=test_case['constraints']
        )
        
        if result['success']:
            print("✅ Secure code generated successfully!")
            print(f"📏 Code length: {len(result['code'])} characters")
            print(f"🤖 Model: {result['model']}")
            
            print("\n🟢 Generated Secure Code:")
            print("-" * 40)
            print(result['code'])
            print("-" * 40)
        else:
            print(f"❌ Failed to generate secure code: {result['error']}")
    
    print("\n" + "=" * 60)
    print("🎯 Secure Code Generation Test Complete")

def main():
    """Main function to demonstrate secure code generation."""
    
    print("🔒 SecureCode-GPT: Vulnerability-Free Code Generation")
    print("=" * 60)
    
    # Example usage
    example_task = "Create a secure function that validates and processes user input without any buffer overflows or format string vulnerabilities"
    
    print(f"\n📝 Example Task: {example_task}")
    print("-" * 40)
    
    result = generate_secure_code(
        task_description=example_task,
        language="C",
        inputs_constraints="Input validation, bounds checking, secure string handling",
        platform="POSIX/Linux"
    )
    
    if result['success']:
        print("✅ Secure code generated successfully!")
        print(f"📏 Code length: {len(result['code'])} characters")
        print(f"🤖 Model: {result['model']}")
        
        print("\n🟢 Generated Secure Code:")
        print("-" * 40)
        print(result['code'])
        print("-" * 40)
    else:
        print(f"❌ Failed to generate secure code: {result['error']}")
    
    # Run comprehensive tests
    test_secure_code_generation()

if __name__ == "__main__":
    main()
