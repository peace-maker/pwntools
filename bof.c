// cl /GS- /Febof64.exe /Fdbof64.pdb /DEBUG:FULL bof.c /link /DYNAMICBASE:NO /DEBUG:FULL
#include <stdio.h>

void win(void) {
    puts("You win!\n");
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc == 1337) {
        win();
    }
    char buf[32];
    gets(buf);
    return 0;
}