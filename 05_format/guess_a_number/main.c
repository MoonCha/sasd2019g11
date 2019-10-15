#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int guess_number(size_t* guesses, unsigned int guess_me){
  char line[32];
  size_t size;
  while(*guesses){
    printf("%zu %s left: \n", *guesses, *guesses > 1 ? "guesses" : "guess");
    if (!fgets(line, sizeof(line), stdin)) {
      printf("Argl! Error!\n");
      return -1;
    }

    size = strlen(line);
    if (size < 1 || line[size - 1] != '\n') {
      printf("Argl! Nope!\n");
      return -1;
    }
    line[size - 1] = '\0';

    printf("Your guess:");
    printf(line);
    printf("\n");
    unsigned int guess = (unsigned int)atol(line);

    if (guess < guess_me) {
      printf("Too small\n");
    } else if(guess > guess_me) {
      printf("Too large\n");
    } else {
      puts("Congratulations!");
      return 1;
    }
    (*guesses)--;
  }
  return 0;
}

void goodbye(void)
{
  puts("bye!");
}

void (*magic)(void) = &goodbye;

int main(int argc, char** argv){

  size_t guesses = 1;
  srand(time(NULL));
  unsigned int guess_me = rand();
  guess_number(&guesses, guess_me);
  magic();
  return 0;
}

void callofbugs(void)
{
  FILE* f;
  f = fopen("flag.txt","r");
  char c = 0;
  if(f)
  {
    c = fgetc(f);
    while (c != EOF)
    {
      printf ("%c", c);
      c = fgetc(f);
    }
  }
}
