#
# Makefile for the guess-a-number game
#
CC      := clang
CFLAGS  := -m32 -Wall -Wno-format-security -pedantic -fno-pie -std=c99 -O1 -g -fstack-protector-all -D_GNU_SOURCE=1

LD      := clang
LDFLAGS := -m32 -Wl,-z,relro -Wl,-z,now -fno-pie -Wl,-Ttext=0x2A200000 -Wl,-u,callofbugs
LIBS    :=

SOURCES    := main.c
EXECUTABLE := guess-a-number
OBJECTS    := $(SOURCES:%.c=%.o)

all: $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

# Link (via C compiler as linker driver)
$(EXECUTABLE): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<
