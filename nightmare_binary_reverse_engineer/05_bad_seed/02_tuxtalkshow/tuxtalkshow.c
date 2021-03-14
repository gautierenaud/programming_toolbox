#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
	unsigned int randNum;
	srand(time(0));

	int iVar1;
	int local_28c;
	int local_288;
	int local_284;
	int local_280;
	int local_27c;
	int local_278;
	int local_274;
	int local_270;
	int local_26c;
	int local_268[8];

	local_280 = 0x79;
	local_27c = 0x12c97f;
	local_278 = 0x135f0f8;
	local_274 = 0x74acbc6;
	local_270 = 0x56c614e;
	local_26c = 0xffffffe2;
	local_268[0] = 0x79;
	local_268[1] = 0x12c97f;
	local_268[2] = 0x135f0f8;
	local_268[3] = 0x74acbc6;
	local_268[4] = 0x56c614e;
	local_268[5] = 0xffffffe2;
	local_28c = 0;
	while (local_28c < 6)
	{
		iVar1 = rand();
		local_268[local_28c] = local_268[local_28c] - (iVar1 % 10 + -1);
		local_28c = local_28c + 1;
	}
	local_288 = 0;
	local_284 = 0;
	while (local_284 < 6)
	{
		local_288 = local_288 + local_268[local_284];
		local_284 = local_284 + 1;
	}

	printf("%d\n", local_288);
}