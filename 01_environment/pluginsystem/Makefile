CC=clang
CFLAGS=-g -O1 -Wall -pedantic -Werror
LIBOPTS=-shared -fPIC
BIN=usrmngr.bin

all: plugins main

clean:
	-$(RM) *.so
	-$(RM) $(BIN)

auth:
	$(CC) $(CFLAGS) $(LIBOPTS) -Wl,-soname,auth.so -o auth.so auth.c

listuser:
	$(CC) $(CFLAGS) $(LIBOPTS) -Wl,-soname,listuser.so -o listuser.so listuser.c

adduser:
	$(CC) $(CFLAGS) $(LIBOPTS) -Wl,-soname,adduser.so -o adduser.so adduser.c

plugins: auth adduser listuser

main:
	$(CC) $(CFLAGS) -Wl,-rpath,. -ldl main.c -o $(BIN)

install: all
	$(INSTALL) -o $(NAME) -m 4755 usrmngr.bin $(INSTALLDIR)
	$(INSTALL) -o $(NAME) -m 755 usrmngr $(INSTALLDIR)
	$(INSTALL) -o $(NAME) -m 755 -t $(INSTALLDIR) auth.so listuser.so adduser.so
	$(INSTALL) -o $(NAME) -m 600 userdata.db $(INSTALLDIR)
