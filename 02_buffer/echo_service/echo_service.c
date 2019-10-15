#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>

#define SUCCESS_MSG "request handled sucessfully\n"

#define ASSERT_RET(expr, msg)          \
  do                                   \
  {                                    \
    if (!(expr))                       \
      err(-1, "[%d] " msg, getpid());  \
  } while (0)

int fd = -1;

void handleRequest();

void terminate(int signum)
{
  _exit(128 + signum);
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
usage:
    printf("usage: %s <port>\n", argv[0] ? argv[0] : "./app");
    return 1;
  }
  fclose(stdin);

  int ret;
  char *end_ptr;
  errno = 0;
  long port = strtol(argv[1], &end_ptr, 10);
  ASSERT_RET(errno == 0, "could not parse port number");

  if (*end_ptr != '\0')
    goto usage;
  if (port < 0 || port > USHRT_MAX)
  {
    printf("port out of range\n");
    return 1;
  }

  // disable core dumps on abort
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = &terminate;
  sigaction(SIGABRT, &action, NULL);

  // do not transform dead child processes into zombies
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_IGN;
  sigaction(SIGCHLD, &action, NULL);

  // create the socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_RET(sockfd >= 0, "could not create socket");
  ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
  ASSERT_RET(ret == 0, "could not set socket options");

  // bind the socket
  struct sockaddr_in address = 
  {
    .sin_family= AF_INET,
    .sin_port = htons(port),
    .sin_addr = 
    {
      .s_addr = htonl(INADDR_LOOPBACK)
    }
  };

  ret = bind(sockfd, (struct sockaddr *)&address, sizeof(address));
  ASSERT_RET(ret == 0, "could not bind address to socket");

  // listen on the socket
  ret = listen(sockfd, 16);
  ASSERT_RET(ret == 0, "could not listen on socket");
  printf("[%d] listening on port %ld...\n", getpid(), port);

  struct sockaddr client_addr;
  socklen_t client_addr_len = sizeof(client_addr);


  while (true)
  {
    errno = 0;
    fd = accept(sockfd, (struct sockaddr *) &address, &client_addr_len);
    if (errno == ECONNABORTED || errno == EINTR)
      continue;

    ASSERT_RET(fd >= 0, "could not accept() on socket");
    pid_t pid = fork();
    if (pid == 0)
    {
      close(sockfd);
      handleRequest(fd);
      send(fd, SUCCESS_MSG, strlen(SUCCESS_MSG), 0);
      close(fd);
      exit(0);
    }
    close(fd);
  }

  ret = close(sockfd);
  ASSERT_RET(ret == 0, "could not close socket");

  return 0;
}

void printFlag()
{
  ssize_t ret;
  printf("[%d] printFlag was called, how could this happen??\n", getpid());
  errno = 0;
  FILE *f = fopen("flag.txt", "r");
  ASSERT_RET(f != NULL, "could not open flag.txt");

  char buf[64];
  memset(buf, 0, sizeof(buf));

  ssize_t read_bytes = fread(buf, 1, sizeof(buf) - 1, f);
  ASSERT_RET(!ferror(f), "failed to read flag");

  ret = send(fd, buf, read_bytes, 0);
  ASSERT_RET(ret >= 0, "failed to send");
  close(fd);
}

void handleRequest()
{
  char buf[1000];
  ssize_t len = 0;
  while ((len = recv(fd, buf, 0x1000, 0)) > 0)
  {
    printf("[%d] received %zd bytes.\n", getpid(), len);
    ssize_t ret = send(fd, buf, len, 0);
    ASSERT_RET(ret >= 0, "failed to send");
  }
  printf("[%d] sent %zd bytes.\n", getpid(), len);
  return;
}
