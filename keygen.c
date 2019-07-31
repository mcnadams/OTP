#include<stdio.h>
#include<stdlib.h>


int main(int argc, char *argv[])
{
	srand(time(NULL));
	
	if(argc < 2){
		fprintf(stderr, "ERROR int keylength required\n");
	}
	
	int keylength = atoi(argv[1]);
	int i;
	int asciival;
	char next;
	for(i = 0; i < keylength; i++){
		//generated ascii values in the range 65 to 91 (A to Z plus one additional)
		asciival = rand() % 27 + 65;
		//if asciival is 91, reassign to value for space character
		if(asciival == 91)
			asciival = 32;
		//next = (char)asciival;
		printf("%c", asciival);
	}
	printf("\n");

	return 0;
}
