# Makefile for this hacklet

PROJECT := my_first_rop_chain

CC       := gcc
CFLAGS 	 := -fno-stack-protector -O0 -Wl,-z,norelro -no-pie -static-libgcc -z noexecstack
LD       := $(CC)
LDFLAGS  := -fno-pie -no-pie -T link.ld -z noexecstack
LIBS     :=

SOURCE     := $(wildcard *.c)
OBJECTS    := $(SOURCE:%.c=%.o) random1.o random2.o
DEPENDS    := $(SOURCE:%.c=%.d)

all: $(PROJECT)

OFFSET1=$(shell bash -c 'echo $$((RANDOM % 4096 + 4096))')
OFFSET2=$(shell bash -c 'echo $$((RANDOM % 4096 + 4096))')

random1.o:
	@echo [DD] $@
	@dd if=/dev/urandom of=$@ bs=1 count=$(OFFSET1)
	@echo [OCOPY] $@
	@objcopy -I binary -O elf64-x86-64 --binary-architecture i386:x86-64 \
	         --rename-section .data=.rodata,alloc,load,readonly,data,contents $@

random2.o:
	@echo [DD] $@
	@dd if=/dev/urandom of=$@ bs=1 count=$(OFFSET2)
	@echo [OCOPY] $@
	@objcopy -I binary -O elf64-x86-64 --binary-architecture i386:x86-64 \
	         --rename-section .data=.rodata,alloc,load,readonly,data,contents $@

$(PROJECT): $(OBJECTS)
	@echo [LD] $@
	@$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

%.o: %.c
	@echo [CC] $<
	@$(CC) $(CFLAGS) -o $@ -c -MMD $<

run:
	@./exploit

clean:
	@rm -f $(PROJECT) $(OBJECTS) $(DEPENDS)

-include $(DEPENDS)
