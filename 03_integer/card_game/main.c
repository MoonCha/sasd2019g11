#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <sys/types.h>
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

#include "msg.h"


#define NUM_PILES 3

struct Game {
  int64_t round;
  int piles[NUM_PILES];
};


void printFlag()
{
  printf("You won?! But that's impossible!\n");
  FILE *f = fopen("flag.txt", "r");
  if (f == NULL)
    err(-1, "could not open flag.txt");
  char buf[128];
  memset(buf, 0, sizeof(buf));
  fread(&buf, 1, sizeof(buf) - 1, f);
  printf("%s", buf);
}

void initPiles(int piles[NUM_PILES])
{
  int sum = 0;
  for (int i = 0; i < NUM_PILES - 1; i++)
  {
    piles[i] = rand() % 52;
    sum ^= piles[i];
  }
  piles[NUM_PILES - 1] = sum;
}

void printPiles(int piles[NUM_PILES])
{
  for (int i = 0; i < NUM_PILES; i++)
  {
    printf("piles[%d] = %d\n", i, piles[i]);
  }
}

void removeCards(int piles[NUM_PILES], int pileNumber, int cards)
{
  // make sure the player doesn't cheat
  if (pileNumber < 0)
    pileNumber = -pileNumber;
  pileNumber = pileNumber % NUM_PILES;

  if (piles[pileNumber] == 0)
  {
    printf("You can't remove cards from an empty pile, cheater!\n");
    exit(1);
  }

  if (cards > piles[pileNumber])
    cards = piles[pileNumber];

  printf("removing %d cards from pile %d\n", cards, pileNumber);
  piles[pileNumber] -= cards;
}

bool checkWin(int piles[NUM_PILES])
{
  for (int i = 0; i < NUM_PILES; i++)
  {
    if (piles[i] != 0)
      return false;
  }
  return true;
}

void playerTurn(struct Game *game)
{
  int pile = -1, cards = -1;
  game->round++;
  printf("Round %ld\n", game->round);
  printPiles(game->piles);
  do
  {
    printf("Pick a pile: ");
    fflush(stdout);
  } while (scanf("%d", &pile) != 1 || pile >= NUM_PILES);

  do
  {
    printf("How many cards do you want to remove: ");
    fflush(stdout);
  } while (scanf("%d", &cards) != 1 || cards <= 0);

  removeCards(game->piles, pile, cards);
}

void computerTurn(struct Game *game)
{
  printf("Alright; It's my turn.\n");
  int sum = 0;
  for (int i = 0; i < NUM_PILES; i++)
    sum ^= game->piles[i];

  for (int i = 0; i < NUM_PILES; i++)
  {
    if (game->piles[i] > (game->piles[i] ^ sum))
    {
      removeCards(game->piles, i, game->piles[i] - (game->piles[i] ^ sum));
      return;
    }
  }

  int bestPile = 0;
  for (int i = 1; i < NUM_PILES; i++)
  {
    if (game->piles[i] > game->piles[bestPile])
      bestPile = i;
  }
  removeCards(game->piles, bestPile, 1);
  return;
}

int play()
{
  struct Game game;
  memset(&game, 0, sizeof(game));
  printMsg();
  printf("Let's play a game:\n"
         "There are %d piles of cards.\n"
         "In each turn you may pick any positive number of cards from one pile only.\n"
         "If you take the last card you win.\n", NUM_PILES);

  initPiles(game.piles);
  while (true)
  {
    playerTurn(&game);
    if (checkWin(game.piles))
    {
      printFlag();
      return 0;
    }
    computerTurn(&game);
    if (checkWin(game.piles))
    {
      printf("You fool! I win.\n");
      return 0;
    }
  }

  return 0;
}


int main()
{
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  srand(time(NULL));

  return play();
}
