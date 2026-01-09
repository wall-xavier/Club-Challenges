#include <stdio.h>

void gadget_farm() {
    __asm__("pop %rdi; ret");
}

void vuln(void){

	char user_input [48];
	puts("What would you like to return today?");
	gets(user_input);
	return;

}

int main(void){
	setvbuf(stdout, NULL, _IONBF,0);
	setvbuf(stdin, NULL, _IONBF, 0);
	puts("Hello, I would like to return something.");
	vuln();
	return 0;
}
