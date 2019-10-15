#include "usrmngr.h"

char plugin_prompt_string[] = "List users";


bool plugin_register(user_management_t* usrmngr)
{
  puts("loading listuser plugin");
  return true;
}


bool plugin_handler(user_management_t* usrmngr)
{
  puts("\nUser Listing:");
  for (size_t i = 0; i < usrmngr->num_users; ++i) {
    user_data_t* user = &usrmngr->users[i];
    printf("uuid=%zu, username=%s\n", i, user->username);
  }
  puts("");
  return true;
}
