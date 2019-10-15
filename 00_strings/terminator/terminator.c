#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "msg.h"

int generateKey() {
    FILE* fp = NULL;
    fp = fopen("sasd.key", "w");

    char buff[20];
    int i = 0;
    while (i < 20) {
        //Random key - make sure no 0 in rand key (1-100) ;)
        buff[i] = (rand() % 100) + 1;
        i++;
    }
    fwrite(buff, sizeof (char), 20, fp);
    fclose(fp);
    return 1;
}

int readKeyFile(char* buff) {
    FILE* fp = NULL;
    fp = fopen("sasd.key", "r");
    fread(buff, sizeof (char), 20, fp);
    fclose(fp);
    int i = 0;
    int zeros = 0;
    while (i < 20) {
        if (buff[i] == 0) {
            zeros++;
            if (zeros > 1)
                return 0;
        }
        i++;
    }

    return 1;
}

void printHex(char* values, int size) {
    int i = 0;
    while (i < size) {
        printf("%X ", values[i]);
        i++;
    }
    printf("\n");
}

void encrypt(char* key) {
    char* message = "You got me";

    int i = 0;
    bool ok = 1;
    printf("Encrypted message:\n");
    while (i < strlen(message)) {
        printf("%c", message[i] ^ key[i]);
        if (message[i] != (message[i] ^ key[i]))
            ok = 0;
        i++;
    }
    printf("\n");

    if (ok)
    {
      FILE* file;
      char c = 0;
      file = fopen("flag.txt","r");
      if(file)
      {
        puts("\n You defeated the terminator :/\n");
        c = fgetc(file);
        while(c != EOF)
        {
          printf("%c",c);
          c = fgetc(file);
        }
        printf("\n");
      }
    }
}

int main(int argc, char** argv)
{
    printMsg();
    FILE* fp = NULL;
    fp = fopen("sasd.key", "r");
    if (!fp) 
    {
        printf("No Keyfile found - generating new sasd.key\n");
        generateKey();
    } else 
    {
        fclose(fp);
    }

    char buff[20] = {0};
    memset(buff, 0, 20);
    if (!readKeyFile(buff)) {
        printf("KeyFile rejected ! Seems to be broken\n");
        return EXIT_FAILURE;
    }

    char key[20] = {0};
    memset(key, 0, 20);
    snprintf(key, 20, "%s", buff);
    //printHex(buff, 20);
    //printHex(key, 20);
    encrypt(key);


    return (EXIT_SUCCESS);
}
