#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

void calc(char *argv[])
{
  float num = 0;
  float sum = 0;
  int count = 0;
  while (scanf("%f", &num) != 0) {
      sum += num;
      count++;
  }
  printf("%f\n", sum / count);
}

int main(int argc, char *argv[])
{
  calc(argv);
}
