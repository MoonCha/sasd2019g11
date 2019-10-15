#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/types.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

#define MAX_BLOCK_NAME_LEN 8
#define MAX_BLOCK_DESCRIPTION_LEN 80

#define RESULT_OK 0
#define RESULT_OOM 1

typedef int result_t;

char flag[128];

int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

struct block
{
  int description_size;
  char *description;
  char name[MAX_BLOCK_NAME_LEN];
  struct block *next;
};

struct block *chain_head;

static struct block **find_block(char *name)
{
  for (struct block **block = &chain_head; *block != NULL; block = &(*block)->next)
  {
    if (strncmp((*block)->name, name, MAX_BLOCK_NAME_LEN) == 0)
      return block;
  }

  return NULL;
}

void str_input(char *dest, size_t strlen) {
  memset(dest, 0, strlen);
  fgets(dest, strlen, stdin);
  for (size_t t = 0; t < strlen; t++) {
    if (dest[t] == '\n') {
      dest[t] = ' ';
    }
  }
}

result_t addBlock()
{
  struct block *new_block = malloc(sizeof(struct block));
  
  if (new_block == NULL)
  {
    return RESULT_OOM;
  }

  int length;
  char sizebuf[8];

  printf("Name: ");
  str_input(new_block->name, MAX_BLOCK_NAME_LEN);
  if (find_block(new_block->name) != NULL)
  {
    puts("a block with that name already exists");
    free(new_block);
    return RESULT_OK;
  }

  printf("Description length: ");
  fgets(sizebuf, sizeof(sizebuf), stdin);
  length = atoi(sizebuf);
  if (length == 0)
  {
    puts("invalid length");
    free(new_block);
    return RESULT_OK;
  }

  // add space for "\n\0"
  length += 2;

  new_block->description_size = length;
  new_block->description = malloc(length);
  
  if (new_block->description == NULL)
  {
    exit(-1);
  }

  printf("Description: ");
  str_input(new_block->description, length);

  new_block->next = chain_head;
  chain_head = new_block;
  return RESULT_OK;
}

result_t deleteBlock()
{
  char name[MAX_BLOCK_NAME_LEN];
  printf("Name: ");
  str_input(name, MAX_BLOCK_NAME_LEN);

  struct block **block = find_block(name);
  if (!block)
  {
    puts("no block with that name exists");
    return RESULT_OK;
  }

  struct block *old_block = *block;
  *block = old_block->next;
  free(old_block);
  return RESULT_OK;
}

result_t modifyBlock()
{
  char name[MAX_BLOCK_NAME_LEN];
  int length;
  char sizebuf[8];

  printf("Name: ");
  str_input(name, MAX_BLOCK_NAME_LEN);

  struct block **block = find_block(name);
  if (!block)
  {
    puts("no block with that name exists");
    return RESULT_OK;
  }

  printf("New name: ");
  str_input((*block)->name, MAX_BLOCK_NAME_LEN);

  printf("New description length: ");
  fgets(sizebuf, sizeof(sizebuf), stdin);
  length = atoi(sizebuf);
  if (length == 0)
  {
    puts("invalid length");
    return RESULT_OK;
  }
  
  // add space for "\n\0"
  length += 2;

  (*block)->description_size = length;

  printf("New description: ");
  str_input((*block)->description, length);
  return RESULT_OK;
}

result_t showChain()
{
  printf("\n=== Block chain ===\n");

  for (struct block *block = chain_head; block != NULL; block = block->next)
  {
    printf("%-8s : ", block->name);
    puts(block->description);
  }

  printf("\n===================\n");
  return RESULT_OK;
}

void printFlag()
{
  printf("Enjoy your flag: %s\n",flag);
}

int main()
{
  FILE *f = fopen("flag.txt", "r");
  assert(f);
  assert(fread(flag, 1, sizeof(flag), f) > 0);
  fclose(f);
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  char buffer[8];
  int choice;
  int result = RESULT_OK;
  setvbuf(stdout,0,2,0);
  setvbuf(stdin,0,2,0);

  while(1)
  {
    puts("----------------------------");
    puts("1. add block to chain");
    puts("2. remove block from chain");
    puts("3. edit block in chain");
    puts("4. print block chain");
    puts("5. exit");
    puts("----------------------------");
    puts("Your choice:");

    fgets(buffer, sizeof(buffer), stdin);
    choice = atoi(buffer);

    switch(choice){
      case 1:
        result = addBlock();
        break;
      case 2:
        result = deleteBlock();
        break;
      case 3:
        result = modifyBlock();
        break;
      case 4:
        result = showChain();
        break;
      case 5:
        exit(0);
        break;
      default:
        puts("invalid choice!!!");
        break;
    }

    if (result != RESULT_OK) {
      exit(-1);
    }
  }

  return 0;
}
