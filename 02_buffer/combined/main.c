#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

void hint() 
{
  //like the butter on the bread for
  //x64 exploitation ;)
  asm("pop %rdi; ret");
}

void readIn() 
{
  char buf[1024];
  read(0, buf, 2048);
}

void echo() 
{
  char buffer[512];
  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
}

int main(int argc, char* argv[]) 
{
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  setbuf(stdout, NULL);
  printf(">");
  echo();
  printf("\n");
  printf(">");
  readIn();
  printf("\nThank you\n");
  return 0;
}
