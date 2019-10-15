# Makefile for this hacklet
PROJECT := callcenter_situations
CC       := gcc 
CFLAGS 	 := -static -lm
LD       := $(CC) 
LDFLAGS  := 
LIBS     := -lm

SOURCE     := $(wildcard *.c)
OBJECTS    := $(SOURCE:%.c=%.o)
DEPENDS    := $(SOURCE:%.c=%.d)

all: $(PROJECT)

$(PROJECT): $(OBJECTS)
	@echo [LD] $@
	@$(LD) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

%.o: %.c
	@echo [CC] $<
	$(CC) $< $(CFLAGS) -o $@ -c -MMD 

run:
	@./exploit

clean:
	@rm -f $(PROJECT) $(OBJECTS) $(DEPENDS)

-include $(DEPENDS)
