# Makefile for this hacklet

PROJECT := cmacro

CC       := gcc
CFLAGS 	 := -std=gnu11 -fstack-protector-all -fpie -O0 -D_GNU_SOURCE
LD       := $(CC)
LDFLAGS  := -pie -Wl,-z,relro,-z,now
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
