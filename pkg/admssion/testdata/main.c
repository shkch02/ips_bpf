#include <stdio.h>

int main() {
    // elfanalyzer가 'printf' 함수를 탐지하는지 확인하기 위함
    printf("Hello, Analyzer!\n"); 

    // elfanalyzer가 '/tmp/test.log' 문자열을 탐지하는지 확인하기 위함
    const char *log_path = "/tmp/test.log";
    printf("Log path is: %s\n", log_path);
    
    return 0;
}
