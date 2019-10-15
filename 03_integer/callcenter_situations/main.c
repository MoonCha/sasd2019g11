#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
    
#include <fenv.h>

typedef void (*function_ptr)(void);
function_ptr handler;
static jmp_buf jmp;

// ---------------------------------------------------------------------------
static void sig_handler(int signum) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
  longjmp(jmp, 1);
}

static void flag() {
    if(!setjmp(jmp)) {
        printf("Nice try ;)\n");
    } else {
        puts("Congratulations Sir, here is your flag.");
        FILE* f = fopen("flag.txt","r");
        char c;
        if(f != NULL)
        {
            c = fgetc(f); 
            while (c != EOF) 
            { 
              printf ("%c", c); 
              c = fgetc(f); 
            }
        }
    }
}

static void inverse() {
    printf("[ Inverse ]\nEnter number: ");
    char in[32];
    fgets(in, sizeof(in), stdin);
    float x = strtof(in, NULL);
    printf("1/%f = %f\n", x, 1.0 / x);
}

static void squareroot() {
    printf("[ Square Root ]\nEnter number: ");
    char in[32];
    fgets(in, sizeof(in), stdin);
    float x = strtof(in, NULL);
    printf("sqrt(%f) = %f\n", x, sqrtf(x));
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGFPE, sig_handler);
    function_ptr handlers[] = {inverse, squareroot, flag};

    feenableexcept(/*FE_DIVBYZERO | */FE_INVALID | FE_OVERFLOW);

    setjmp(jmp);
    int show = 1;

    while(1) {
        if(show) {
            printf("\n[ Hello Sir, what do you want?]\n");
            printf("  1...Inverse\n");
            printf("  2...Square Root\n");
            printf("  3...Give flag now :D\n");
            printf("q.....Exit\n");
        }
        show = 0;

        char buf[8];
        memset(buf, 0, sizeof(buf));
        fgets(buf, 8, stdin);

        int c = buf[0];
        if(c == 'q') exit(0);
        c -= '1';

        puts("\033[2J");
        if(c >= 0 && c < sizeof(handlers) / sizeof(handlers[0])) {
            handlers[c]();
            show = 1;
        }
    }
}
