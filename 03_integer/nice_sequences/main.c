#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

void fib(unsigned int n);
void recaman(unsigned int n);
void triangular_numbers(unsigned int n);

//fun function
void get_fl4g() 
{
  FILE* file;
  file = fopen("flag.txt","r");
  char c;
  if(file)
  {
    while((c=fgetc(file))!=EOF) 
    {
      printf("%c",c);
    }
    fclose(file);
  }
}

void fib(unsigned int n) 
{
  if(n >= 200)
  {
    puts("your number is too large. The maximum is 199 :)");
    return;
  }
  int prev[n+2];
  int i; 
  prev[0] = 0;
  prev[1] = 1;

  printf("%d %d ", prev[0],prev[1]);
  for (i = 2; i <= n; i++) 
  { 
    prev[i] = prev[i-1] + prev[i-2]; 
    printf("%d ", prev[i]);
  } 
  return;
}

void recaman(unsigned int n) 
{
  if(n >= 100)
  {
    puts("your number is too large. The maximum is 99 :)");
    return;
  }

  int arr[n];
  // First term of the sequence is always 0 
  arr[0] = 0;
  printf("%d ", arr[0]);

  // Fill remaining terms using recursive 
  // formula. 
  for (int i=1; i< n; i++)
  {
    int curr = arr[i-1] - i;
    int j; 
    for (j = 0; j < i; j++)
    {
        // If arr[i-1] - i is negative or 
        // already exists. 
        if ((arr[j] == curr) || curr < 0) 
        { 
            curr = arr[i-1] + i;
            break;
        }
    }
    arr[i] = curr; 
    printf("%d ", arr[i]); 
  } 
}

void triangular_numbers(unsigned int n) 
{
  if(n >= 300)
  {
    puts("your number is too large. The maximum is 299 :)");
    return;
  }
  int i = 1, j = 1, k = 1; 
  for (i = 1; i <= n; i++) 
  { 
    printf("%d ", k); 
    j = j + 1;
    k = k + j;
  }
}

void handle_function(int option,uint64_t number)
{
  void (*func_ptr[3])() = {fib, recaman, triangular_numbers};
  puts("Nice, everyone loves sequences ;)");
  (*func_ptr[option])(number);
}

int main(int argc, char* argv[]) 
{
  gid_t gid = getegid();
  setresgid(gid,gid,gid);
  setbuf(stdout, NULL);

  if(argc != 3)
  {
    puts("Choose the sequence type and the length of the sequence to print");
    printf("Usage: %s <option> <length>\n", argv[0]);
    puts("Available options:");
    puts("  0 ... fib");
    puts("  1 ... recaman");
    puts("  2 ... triangular_numbers");
    return -1;
  }

  int option = atoi(argv[1]);
  uint64_t number = strtoull(argv[2],NULL,10);

  if(option > 3)
  {
    puts("Invalid option");
    return -1;
  }

  handle_function(option,number);
  puts("\nBye!");
  return 0;
}
