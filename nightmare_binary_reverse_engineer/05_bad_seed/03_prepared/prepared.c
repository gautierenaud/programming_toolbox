#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
	unsigned int randNum;
	srand(time(0));
	for (int i = 0; i < 50; ++i)
	{
		randNum = rand() % 100;
		printf("%d\n", randNum);
	}
}