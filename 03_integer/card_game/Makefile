# Makefile for this hacklet

PROJECT := card_game

CC       := gcc
CFLAGS 	 := -std=gnu11 -fstack-protector-all -O0 -Wl,-z,norelro
LD       := $(CC)
LDFLAGS  :=
LIBS     :=

BUILDDIR := build
SOURCE     := $(wildcard *.c)
OBJECTS    := $(SOURCE:%.c=$(BUILDDIR)/%.o)
DEPENDS    := $(SOURCE:%.c=$(BUILDDIR)/%.d)

all: $(PROJECT)

$(PROJECT): $(OBJECTS)
	@echo [LD] $@
	@$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

$(BUILDDIR):
	@mkdir $(BUILDDIR)

$(BUILDDIR)/%.o: %.c $(BUILDDIR)
	@echo [CC] $<
	@$(CC) $(CFLAGS) -o $@ -c -MMD $<

run:
	@./exploit

clean:
	@rm -rf $(BUILDDIR)

.PHONY: clean

-include $(DEPENDS)
