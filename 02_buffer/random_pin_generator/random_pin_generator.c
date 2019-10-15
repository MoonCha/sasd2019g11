#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void admin(){
	printf("Launching administrative shell...\n");
	FILE* f = fopen("flag.txt", "r");
	char buffer[1024] = {0,};
	size_t len = fread(buffer, 1, sizeof(buffer), f);
	printf(">>%s\n", buffer);
	//system("cat flag.txt");
}

void do_stuff()
{
	struct{
		int i;
		char buffer_read[4];
		int luck;
		int seed_size;
		char seed[4];
	} x;
	memset(&x, 0x00, sizeof(x));

	x.luck = rand() % 101;

	for (x.i = 0; x.i < 4; x.i++) {
		printf("Enter digit %zu of your old PIN\n", x.seed_size);
		if(fgets(x.buffer_read, 10, stdin) == 0 || x.buffer_read[0] == '\n') {
			printf("Failed to read digit %x\n", x.seed_size);
			return;
		}
		x.seed[x.seed_size++] = x.buffer_read[0];
	}
	
	printf("Your luckyness coefficient is %x%%.\n", x.luck);
	if (x.luck != 100) {
		printf("Sorry, i have no PIN code for you today.");
		exit(1);
	}

	srand(x.seed[3]);
	printf("Your old PIN was %c%c%c%c\n",
		x.seed[0], x.seed[1], x.seed[2], x.seed[3]);
	printf("Here's your new secure PIN: %04d\n", rand() % 10000);
}

int main(int argc, char** argv){
	printf("Welcome to the Random PIN Generator. It randomly decides wether to generate a PIN.\n");
	do_stuff();
	printf("bye\n");
	exit(0);
}
