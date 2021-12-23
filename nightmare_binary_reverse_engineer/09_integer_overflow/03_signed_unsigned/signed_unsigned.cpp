#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	puts("This is just a well documented C file explaining a potential attack.");
	puts("Thing is, how signed and unsigned values are store is different.");
	puts("So if we were to evaluate a signed integer as an unsigned integer, or vice versa, it would see a different "
		 "value than what it was assigned.");
	puts("Let's see an example.\n");

	unsigned long l0 = 0xfacade54facade;
	printf("We have initialized an unsigned long with the value: 0x%lx\n\n", l0);

	puts("First we will compare it as an unsigned integer to the value we initialized it to.");

	if (l0 == 0xfacade54facade)
	{
		puts("Check 0 passed.\n");
	}
	else
	{
		puts("Check 0 failed.\n");
	}

	puts("Now we will compare it as a signed integer to the value we initialized it to.");

	if ((signed)l0 == 0xfacade54facade)
	{
		puts("Check 1 passed.\n");
	}
	else
	{
		puts("Check 1 failed.\n");
	}

	puts("As you can see, when we cast it to a signed integer it was perceived as a different value, and thus failed "
		 "the check.");
	puts("You will find this type of bug around where it compares a signed value as unsigned or vice versa.");
	puts("It is usually just one step in the process of getting code execution.");
}