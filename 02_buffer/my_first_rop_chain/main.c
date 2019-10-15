#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);


#define ROP_SECTION  __attribute__((__section__(".myropsection")))

volatile char* fun =  "I have got really much fun using my favourite shell: /bin/sh";
volatile char* fun2 = "Others prefer using cat flag.txt";

extern int __ROP_START[];
extern int __ROP_END[];

void ROP_SECTION hint()
{
  //like the butter on the bread for
  //x64 exploitation ;)
  //asm volatile("pop; ret");
  asm volatile("pop %rdi; ret");
}

void ROP_SECTION whoami()
{
  //here should be system my friend :P
  puts("0");
}

typedef struct __attribute__((packed)) {
  char data[0x70];
  void (*fptr)(void);
} buffer_t;

void command() {

  buffer_t buffer = {
    .data = {0,},
    .fptr = &whoami,
  };

  read(0, &buffer.data, 120);

  if ((void*)buffer.fptr < (void*)__ROP_START ||
      (void*)buffer.fptr > (void*)__ROP_END) {
    printf("Pointer %p is corrupted!\n", buffer.fptr);
    printf("Function must be in range %p-%p\n", __ROP_START, __ROP_END);
    exit(1);
  }
  buffer.fptr();
  printf("Input was: %s\n", buffer.data);
  printf("Try harder...\n");
}

int main(int argc, char** argv) 
{
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  setbuf(stdout, NULL);
  puts("Welcome to your first ROP chain");
  puts("Please keep in mind that you are not allowed to use Pwntools helper scripts for this hacklet");
  command();
  return 0x539;
}
