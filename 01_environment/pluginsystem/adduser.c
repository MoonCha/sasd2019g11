#include "usrmngr.h"

char plugin_prompt_string[] = "Add user";


bool plugin_register(user_management_t* usrmngr)
{
  puts("loading adduser plugin");
  return true;
}


bool plugin_handler(user_management_t* usrmngr)
{
  usrmngr->num_users++;
  usrmngr->users = realloc(usrmngr->users, usrmngr->num_users * sizeof(user_data_t));
  user_data_t* user = &usrmngr->users[usrmngr->num_users - 1];

  puts("Please input username: ");
  fgets(user->username, MAX_USERNAME_LENGTH, stdin);
  puts("Please input password: ");
  fgets(user->password, MAX_PASSWORD_LENGTH, stdin);

  printf("Added user %s with password %s\n", user->username, user->password);

  return true;
}
