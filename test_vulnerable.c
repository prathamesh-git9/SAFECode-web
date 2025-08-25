#include <stdio.h>
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
    
    // Vulnerable: integer overflow
    int a = 2147483647;
    int b = 1;
    int result = a + b; // This will overflow
    
    // Vulnerable: null pointer dereference
    char *ptr = NULL;
    *ptr = 'x'; // This will crash
    
    return 0;
}
