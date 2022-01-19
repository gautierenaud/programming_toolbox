#include <chrono>
#include <iostream>
#include <random>
#include <vector>

using namespace std;

static void searchNumber(const vector<long> &sortedVector, const long numberToSearch)
{
	auto start = chrono::high_resolution_clock::now();

	long lowerBound = 0;
	long upperBound = sortedVector.size();
	bool found = false;
	while (!found)
	{
		long middleIndex = (lowerBound + upperBound) / 2;

		if (sortedVector[middleIndex] == numberToSearch)
		{
			found = true;
		}
		else if (sortedVector[middleIndex] > numberToSearch)
		{
			upperBound = middleIndex;
		}
		else
		{
			lowerBound = middleIndex;
		}
	}

	auto finish = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsed = finish - start;
	cout << "Took " << elapsed.count() << "s to find element " << numberToSearch << endl;
}

static vector<long> generateSortedStructure(const long &size)
{
	vector<long> result;
	result.reserve(size);

	for (long i = 0; i < size; ++i)
	{
		result.push_back(i);
	}

	return result;
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