#!/bin/bash

# Only run this script inside Docker as root user!
# It will change file permissions and ownership

chmod 500 exploit
chown -R exploit:exploit .
chown hacklet:hacklet main.elf
chmod 111 main.elf
sudo -u exploit ./exploit
