#include "usrmngr.h"


void* load_plugin(char* pluginname)
{
  void* lib = dlopen(pluginname, RTLD_LAZY);
  if (!lib) {
    printf("failed to load %s: %s\n", pluginname, dlerror());
    return NULL;
  }
  return lib;
}


bool register_plugin(void* plugin, user_management_t* usrmngr)
{
  plugin_register_fp regfunc = (plugin_register_fp)dlsym(plugin, "plugin_register");
  if (regfunc == NULL) {
    fputs("failed to load plugin_register function\n", stderr);
    return false;
  }
  // call the register function
  if (!regfunc(usrmngr)) {
    fputs("failed to register plugin\n", stderr);
    return false;
  }

  void* handler = dlsym(plugin, "plugin_handler");
  if (handler == NULL) {
    fputs("failed to load plugin_handler\n", stderr);
    return false;
  }
  char* handler_str = (char*)dlsym(plugin, "plugin_prompt_string");

  usrmngr->prompt.handler[usrmngr->prompt.num_handler] = handler;
  usrmngr->prompt.handler_strs[usrmngr->prompt.num_handler] = handler_str;
  usrmngr->prompt.num_handler++;

  return true;
}


bool load_data(user_management_t* usrmngr)
{
  puts("Loading user data...");

  char buf[MAX_USERNAME_LENGTH + MAX_PASSWORD_LENGTH + 2] = {0, };
  FILE* f = fopen("./userdata.db", "r");
  if (f == NULL) {
    return false;
  }
  char* ret = fgets(buf, sizeof(buf) - 1, f);
  size_t i = 0;
  while (ret != NULL) {

    usrmngr->num_users++;
    void* newbuf = realloc(usrmngr->users,
                           usrmngr->num_users * sizeof(user_data_t));
    if (!newbuf) {
      return false;
    }
    usrmngr->users = newbuf;
    memset(usrmngr->users[i].username, 0, MAX_USERNAME_LENGTH);
    memset(usrmngr->users[i].password, 0, MAX_PASSWORD_LENGTH);

    char* term = strchr(buf, ':');
    *term = '\0';
    term++;
    strncpy(usrmngr->users[i].username, buf, MAX_USERNAME_LENGTH);
    char* nl = strchr(term, '\n');
    if (nl) {
      *nl = '\0';
    }
    strncpy(usrmngr->users[i].password, term, MAX_PASSWORD_LENGTH);

    ret = fgets(buf, sizeof(buf) - 1, f);
    ++i;
  }

  return true;
}


bool init_user_manager(user_management_t* usrmngr)
{
  bool ret = true;

  // init with data
  ret &= load_data(usrmngr);

  // load default plugins
  void* plugin = load_plugin("auth.so");
  if (plugin == NULL) {
    return false;
  }
  ret &= register_plugin(plugin, usrmngr);

  plugin = load_plugin("adduser.so");
  if (plugin == NULL) {
    return false;
  }
  ret &= register_plugin(plugin, usrmngr);


  plugin = load_plugin("listuser.so");
  if (plugin == NULL) {
    return false;
  }
  ret &= register_plugin(plugin, usrmngr);

  return ret;
}


void display_prompt(user_management_t* usrmngr)
{
  int choice = -1;
  char choice_s[10];
  puts("Please select one of the following actions:");
  for (size_t i = 0; i < usrmngr->prompt.num_handler; ++i) {
    printf("%zu. %s\n", i, usrmngr->prompt.handler_strs[i]);
  }
  fputs("choice: ", stdout);
  fgets(choice_s, sizeof(choice_s), stdin);
  sscanf(choice_s, "%d\n", &choice);

  if (choice < 0 || choice >= ((int)usrmngr->prompt.num_handler)) {
    puts("Invalid choice...");
    return;
  } else {
    // call handler function
    plugin_handler_fp func = (plugin_handler_fp)usrmngr->prompt.handler[choice];
    func(usrmngr);
  }
}


int main(void)
{
  user_management_t* usrmngr = calloc(sizeof(user_management_t), 1);
  if (!usrmngr) {
    puts("Out of memory\n");
    return -1;
  }
  usrmngr->users = NULL;
  if (! init_user_manager(usrmngr)) {
    return -1;
  }

  while (true) {
    display_prompt(usrmngr);
  }

  return 0;
}
