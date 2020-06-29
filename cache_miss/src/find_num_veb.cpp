#include "../thirdparties/veb.cpp"
#include "../thirdparties/veb.hpp"
#include <chrono>
#include <iostream>
#include <random>

using namespace std;

static void searchNumber(TvEB* tree, const long numberToSearch)
{
	auto start = chrono::high_resolution_clock::now();

    vEB_find(tree, numberToSearch);

	auto finish = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsed = finish - start;
	cout << "Took " << elapsed.count() << "s to find element " << numberToSearch << endl;
}

static TvEB* generateSortedStructure(const long &size)
{
	TvEB *tree = new TvEB(size);
	for (long i = 0; i < size; ++i)
	{
		vEB_insert(tree, i);
	}

    return tree;
}

static long getRandomNumberToSearch(const long &maxNum)
{
	// obtain a random number from hardware
	std::random_device rd;
	// seed the Mersenne Twister pseudo-random generator of 32-bit numbers with a state size of 19937 bits
	std::mt19937 gen(rd());
	// define the range
	std::uniform_int_distribution<> distr(0, maxNum);

	return distr(gen);
}

int main()
{
	constexpr long size = 10000000;

	auto sortedStructure = generateSortedStructure(size);
	long numberToSearch = getRandomNumberToSearch(size - 1);

	searchNumber(sortedStructure, numberToSearch);
}