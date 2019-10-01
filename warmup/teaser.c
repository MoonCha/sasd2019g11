#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct user
{
    char username[31];
    char restricted;
};

#define NO_USERS 10

struct config
{
  struct user current_user;
  char debug;
  char dummy[31];
  struct user users[NO_USERS];
  char flag_buffer[1024];
} config = {0};

void print_flag()
{
    if (config.debug != 'd')
    {
        printf("Not that easy!\n");
        return;
    }

    FILE* f = fopen("flag.txt", "r");
    size_t len = fread(config.flag_buffer, 1, sizeof(config.flag_buffer), f);
    printf(">> [REDACTED] (Sorry, we can't actually show you the flag. It's secret.)\n");
    printf(">> But we cached the flag in case you need it later :)\n");
    fclose(f);
}

int get_user_id()
{
    char idbuf[11];

    printf("Enter user ID (0-%d): ", NO_USERS - 1);
    char* res = fgets(idbuf, sizeof(idbuf), stdin);
    if (res == NULL)
        return -1;

    return atoi(idbuf);
}

char* get_username(char* buf, size_t buf_size)
{
    printf("Enter username: ");
    char* res = fgets(buf, buf_size, stdin);
    if (res == NULL)
        return NULL;

    // Delete \n
    if (strlen(res) > 0 && res[strlen(res) - 1] == '\n')
        res[strlen(res) - 1] = 0;

    return res;
}

void admin()
{
    printf("Launching administrative shell...\n");

    while (1)
    {
        char cmd[32];

        printf("%s:%s> ", config.current_user.username, config.debug == 'd' ? "debug" : "admin");
        if (fgets(cmd, sizeof(cmd), stdin) == NULL)
            return;

        // Delete \n
        if (strlen(cmd) > 0 && cmd[strlen(cmd) - 1] == '\n')
            cmd[strlen(cmd) - 1] = 0;

        if (strcmp(cmd, "flag") == 0)
        {
            print_flag();
        }
        else if (strcmp(cmd, "register") == 0)
        {
            printf("Registering a new user\n");
            int id = get_user_id();
            char name[31];

            if (get_username(name, sizeof(name)) == NULL)
                return;

            strncpy(config.users[id].username, name, 30);
            config.users[id].restricted = 1;
        }
        else if (strcmp(cmd, "print") == 0)
        {
            int id = get_user_id();

            printf("Username: %s\nRestricted: %d\n",
                    config.users[id].username,
                    config.users[id].restricted);
        }
        else if (strcmp(cmd, "exit") == 0)
        {
            break;
        }
        else
        {
            printf("Unknown command %s\n", cmd);
        }
    }
}

int main(int argc, char** argv)
{
    printf("Welcome to the Login service.\n");
    printf("Please enter username: ");

    config.current_user.restricted = 1;
    if (fgets(config.current_user.username, 0x20, stdin) == NULL)
    {
        printf("Dying pretty hard :/\n");
        return 1;
    }

    if (!config.current_user.restricted)
    {
        admin();
    }
    else
    {
        printf("You are restricted from performing this action.\n"
               "Please contact your local system administrator if you see this message in error\n");
    }
}
