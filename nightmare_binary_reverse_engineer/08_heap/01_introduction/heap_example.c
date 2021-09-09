#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void simple_example()
{
	char *ptr;
	ptr = malloc(0x1a);
	strcpy(ptr, "panda");
	free(ptr);
}

void tcache()
{
	char *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7;

	p0 = malloc(0x10);
	p1 = malloc(0x10);
	p2 = malloc(0x10);
	p3 = malloc(0x10);
	p4 = malloc(0x10);
	p5 = malloc(0x10);
	p6 = malloc(0x10);
	p7 = malloc(0x10);

	malloc(10); // Here to avoid consolidation with Top Chunk

	free(p0);
	free(p1);
	free(p2);
	free(p3);
	free(p4);
	free(p5);
	free(p6);
	free(p7);
}

void large_bin()
{
	char *ptr;
	ptr = malloc(0x410);
	malloc(0x10);
	free(ptr);
	malloc(0x420); // b *large_bin+53
}

void allocate_from_tcache()
{
	char *ptr;
	ptr = malloc(0x410);
	malloc(0x10);
	free(ptr);
	malloc(0x200); // b *allocate_from_tcache+53
}

void top_chunk()
{
	char *p0, *p1;

	p0 = malloc(0x10); // b *top_chunk+17
	p1 = malloc(0xf0); // b *top_chunk+31

	free(p1); // b *top_chunk+47
	free(p0);
}

int main(void)
{
	// simpleExample();
	// tcache();
	// large_bin();
	// allocate_from_tcache();
	top_chunk();
}