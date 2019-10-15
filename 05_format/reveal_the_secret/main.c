#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//Exploit a format string vulnerability in order to make the program reveal the hidden
//NSA information ;)
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#define INFO(...) do { fprintf(stdout, __VA_ARGS__); fflush(stdout); } while(0)
#define WARNING(msg) fprintf(stdout, "[WARN] \033[0;33m%s\033[0m\n", msg)
#define ERROR(msg) fprintf(stderr, "[ERR] \033[0;31m%s\033[0m\n", msg)
#define LOG(msg) fprintf(stdout, "\033[0;34m%s\033[0m", msg)

#define PRINT_HEX(buf, len) do { for (size_t i = 0; i < len; i++) printf("%02x", (unsigned char)buf[i]); } while(0)

char tmp[256];
void logging(char* cmd) {
  if (strlen(cmd) >= sizeof(tmp)) {
    ERROR("Stop talkin' dude!\n");
    exit(1);
  }
  snprintf(tmp, sizeof(tmp), "[%lu]: %s\n", time(NULL), cmd);
  LOG(tmp);
}

int command(char* cmd, char* arg){
  printf("Yo dawg, what r ya doin right now?\n");
  logging(cmd);
  if (!strcmp(cmd, "gimme-rnd")) {
    INFO("One wisdom a day...");
    system("fortune -s");
  } else if (!strcmp(cmd, "gimme-null")) {
    INFO("Reading void: ");
    system("cat /dev/null");
    INFO("Are you happy now?\n");
  } else if (!strcmp(cmd, "gimme-flag")) {
    INFO("Nice try. Forget it!\n");
  } else if (!strcmp(cmd, "gimme-cipher")) {
    if (!arg) {
      WARNING("Provide hash input (4 chars)!\n");
    } else {
      LOG("Your hash seed: ");
      INFO(arg);
      LOG("\n");
      if (strlen(arg) > 4) {
        WARNING("Provide hash input (4 chars)!\n");
      } else {
        INFO("Here's your hash: ");
        snprintf(tmp, sizeof(tmp), "echo %s | sha1sum", arg);
        system(tmp);
      }
    }
  } else {
    puts("Didn't get it :{\n");
  }
  return 0;
}

void encrypt(char* msg, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  assert(fd >= 0);
  char otp[len];
  assert(read(fd, otp, len) == len);
  for (size_t i = 0; i < len; i++) {
    msg[i] ^= otp[i];
  }
}

int main(int argc, char** argv) {
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  char* nsa_document = "\n\
  Dear Mr President,\n\
  we found out a very import information";
  FILE* f = fopen("flag.txt", "r");
  assert(f);
  char secret[128] __attribute__((aligned (8)));
  assert(fread(secret, 1, sizeof(secret), f) > 0);

  if(argc >= 2) {
    if (command(argv[1], argc >= 2 ? argv[2] : NULL)) {
      encrypt(secret, sizeof(secret));
      PRINT_HEX(secret, sizeof(secret));
    }
  } else {
    WARNING("I am single-threaded!\n");
    INFO("Usage: %s <option>\n", argv[0]);
    INFO("Available options:\n");
    INFO("  gimme-rnd\n");
    INFO("  gimme-null\n");
    INFO("  gimme-flag\n");
    INFO("  gimme-cipher\n");
  }

  // safe cleanup
  memset(secret, 0, sizeof(secret));
}
