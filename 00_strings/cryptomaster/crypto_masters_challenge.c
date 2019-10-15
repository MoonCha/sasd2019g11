#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>


#define SECRET_SIZE 32


void print_as_hex(uint8_t* data, size_t len)
{
  for (size_t i = 0; i < len; ++i) {
    printf("%x", data[i]);
  }
}


void init_secret(char* secret, size_t size)
{
  FILE* urandom = fopen("/dev/urandom", "r");
  if (urandom != NULL) {
    fread(secret, size-1, 1, urandom);
    secret[size-1] = '\0';
    fclose(urandom);
  } else {
    size_t i = 0;
    srandom(((long)((int*) &i)) ^ time(NULL));
    for (i = 0; i < size - 1; ++i) {
      secret[i] = random() % 26 + 'a';
    }
    secret[size-1] = '\0';
  }
}


void hash(char* data, size_t len, uint8_t* hval)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md = EVP_sha256();
  unsigned int md_len;

  mdctx = EVP_MD_CTX_create();
  if (!mdctx) {
    return;
  }
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, data, len);
  EVP_DigestFinal_ex(mdctx, hval, &md_len);
  EVP_MD_CTX_destroy(mdctx);
}


void printFlag()
{
  puts("\n\nCongrats you got it ;)");
  FILE* f;
  f = fopen("flag.txt","r");
  if(f)
  {
    char c = fgetc(f);
    while(c != EOF)
    {
      printf("%c",c);
      c = fgetc(f);
    }
    printf("\n");
  }
}


int main(void)
{
  char userinput[SECRET_SIZE] = {0, };
  char secret[SECRET_SIZE] = {0, };
  uint8_t inp_md[SHA256_DIGEST_LENGTH] = {0, };
  uint8_t sec_md[SHA256_DIGEST_LENGTH] = {0, };

  init_secret(secret, sizeof(secret));
  hash(secret, sizeof(secret), sec_md);
  memset(secret, 0, sizeof(secret));

  puts("[Crypto-Master] HAHAHAHAHAHA! You, foolish dogecoin miner, "
      "you cannot guess the secret!");
  printf("[Crypto-Master] You can even have the sha1 hash - ");
  print_as_hex(sec_md, sizeof(sec_md));
  puts("");
  puts("");
  puts("...");
  puts("");
  puts("[] The crypto master taunts you. Can you prove him wrong? "
      "What's the secret?");

  fgets(userinput, sizeof(userinput), stdin);
  hash(userinput, SECRET_SIZE, inp_md);

  if (memcmp(sec_md, inp_md, strlen((char*)inp_md)) == 0) {
    puts("[Crypto-Master] NOOOOOOOOO!!!");
    puts("[Crypto-Master] How did you defeat my cryptomagical skills? HOOOW?");
    puts("[] Crypto-Master dropped magic wand of SASD flags!");
    printFlag();
    return EXIT_SUCCESS;
  } else {
    puts("[Crypto-Master] MUHAHAHAHAH! That's not the secret!");
    printf("[Crypto-Master] You thought that ");
    print_as_hex(inp_md, sizeof(inp_md));
    puts(" was the answer?");
    puts("[Crypto-Master] You are doomed to program COBOL for the rest "
        "of your pittyful life!");
  }

  return EXIT_FAILURE;
}
