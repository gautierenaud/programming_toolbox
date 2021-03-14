#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    unsigned int randNum;
    srand(time(0));
    randNum = rand();
    printf("%d\n", randNum);
}