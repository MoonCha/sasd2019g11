CC     := gcc 
CFLAGS := -Wall -std=c99 -Wl,-z,now -pedantic -O0 -ggdb -lm -m32

FILE := calculator

all: ${FILE}

clean:
	rm -f ${FILE}

${FILE}: ${FILE}.c
	$(CC) $< -o $@  $(CFLAGS)
