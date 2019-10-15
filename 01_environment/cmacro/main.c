#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <err.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

char *DEFAULT_LIBS[] = {"stdio.h", "string.h", "errno.h", "signal.h",
  "unistd.h", "limits.h", "float.h", "sys/syscall.h", NULL};

#define MARKER "########################################\n"

int main(int argc, char **argv)
{
  int inpipe[2], outpipe[2];
  int pid;
  FILE *infile, *outfile;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  if (argc < 2)
  {
    fprintf(stderr, "Resolve a C MACRO\n\n");
    fprintf(stderr, "usage: %s [header-files] MACRO\n", argv[0]);
    fprintf(stderr, "example: %s SIGSEGV\n", argv[0]);
    return 1;
  }

  pipe2(inpipe, O_CLOEXEC);
  pipe2(outpipe, O_CLOEXEC);

  pid = fork();
  if (pid == -1)
    err(-1, "failed to fork");

  if (pid == 0)
  {
    // child
    dup2(inpipe[0], STDIN_FILENO);
    dup2(outpipe[1], STDOUT_FILENO);

    char *args[] = {"gcc", "-P", "-E", "-I.", "-", NULL};
    execvp(args[0], args);
    err(-1, "exec failed");
  }

  // parent
  close(inpipe[0]);
  close(outpipe[1]);
  infile = fdopen(inpipe[1], "w");
  outfile = fdopen(outpipe[0], "r");
  if (!infile || !outfile)
    err(-1, "fdopen failed");

  for (char **lib = DEFAULT_LIBS; *lib; ++lib)
    fprintf(infile, "#include <%s>\n", *lib);

  for (int i = 1; i < argc - 1; ++i)
    fprintf(infile, "#include <%s>\n", argv[i]);

  fprintf(infile, "%s\n", MARKER);
  fprintf(infile, "%s", argv[argc - 1]);
  fflush(infile);
  write(inpipe[1], "", 0);
  fclose(infile);

  char *line = NULL;
  size_t n = 0;
  bool marker_seen = false;
  while (getline(&line, &n, outfile) > 0)
  {
    if (marker_seen)
      printf("%s", line);
    else if (strcmp(line, MARKER) == 0)
      marker_seen = true;
  }

  int stat = -1;
  waitpid(pid, &stat, 0);

  if (WEXITSTATUS(stat) != 0)
  {
    fprintf(stderr, "child died with exit code %d\n", WEXITSTATUS(stat));
    return 1;
  }

  return 0;
}
