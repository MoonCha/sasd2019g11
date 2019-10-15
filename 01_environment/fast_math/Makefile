# Makefile for this hacklet


CC       := gcc -no-pie
CFLAGS 	 := -std=c99 -Wl,-z,relro -Wl,-z,now -pedantic -O0 -ggdb -fno-stack-protector
LD       := $(CC)
LDFLAGS  := 
LIBS     :=

SOURCE     := $(wildcard *.c)
OBJECTS    := $(SOURCE:%.c=%.o)
DEPENDS    := $(SOURCE:%.c=%.d)
PROGS      := $(SOURCE:%.c=%)

all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS)  -o $@ $<

clean:
	@rm -f $(PROGS) $(OBJECTS) $(DEPENDS)
