
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define SAMPLES 1000

void calc(char *argv[])
{
  struct stat info_arg;
  struct stat info_main;
  int pipe_fds1[2];
  int pipe_fds2[2];
  char buf[512];
  int n;

  // check file ownership is equal
  if (stat(argv[1], &info_arg) < 0 ||
      stat("main.elf", &info_main) ||
      info_arg.st_uid != info_main.st_uid)
  {
    printf("executable owner is wrong\n");
    exit(-1);
  }

  if (pipe(pipe_fds1) < 0 ||
      pipe(pipe_fds2) < 0)
  {
    printf("Unable to create pipes\n");
    exit(-1);
  }

  // prepare test vectors
  srand(42);
  size_t max = atoi(argv[2]);
  float *samples = calloc(SAMPLES, sizeof(float));
  if (!samples)
  {
    printf("Out of memory\n");
    exit(-1);
  }
  for (int i = 0; i < SAMPLES; i++)
  {
    for (int j = 0; j < max; j++)
    {
      samples[i] += (float) rand() / RAND_MAX;
    }
  }

  // run the computation
  pid_t pid = fork();
  if (pid == -1)
  {
    printf("Unable to fork\n");
    exit(-1);
  }
  else if (pid == 0)
  {
    if(dup2(pipe_fds1[1], 1) < 0 ||
       dup2(pipe_fds2[0], 0) < 0)
    {
      printf("Unable to duplicate pipes\n");
      exit(-1);
    }
    execv(argv[1], argv);
    perror(argv[1]);
    exit(-1);
  }
  else
  {
    for (int i = 0; i < SAMPLES; i++)
    {
      dprintf(pipe_fds2[1], "%f\n", samples[i]);
    }
    dprintf(pipe_fds2[1], "end\n");
    if ((n = read(pipe_fds1[0], buf, sizeof(buf) - 1)) >= 0)
    {
      buf[n] = '\0';
      fprintf(stderr, "Result: %s", buf);
    }
    else
    {
      fprintf(stderr, "read failed\n");
      perror("read");
    }
  }
}

int main(int argc, char *argv[])
{
  if (argc < 3)
  {
    printf("Usage: %s [average|sum] <max amount>\n", argv[0]);
    return -1;
  }
  puts("Welcome to the fast math service...");
  calc(argv);
  return 0;
}
