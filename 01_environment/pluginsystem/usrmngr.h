#ifndef USRMNGR_H
#define USRMNGR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <string.h>


#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 512
#define MAX_PLUGINS 128


typedef void* plugin_data_t;

typedef struct {
  char username[MAX_USERNAME_LENGTH];
  char password[MAX_PASSWORD_LENGTH];
  plugin_data_t plugin_data[MAX_PLUGINS];
} user_data_t;


typedef struct {
  void* handler[MAX_PLUGINS];
  char* handler_strs[MAX_PLUGINS];
  size_t num_handler;
} prompt_t;


typedef struct {
  size_t num_plugin;
  prompt_t prompt;

  user_data_t* users;
  size_t num_users;
} user_management_t;


typedef bool (*plugin_register_fp)(user_management_t*);
typedef bool (*plugin_handler_fp)(user_management_t*);


#endif
