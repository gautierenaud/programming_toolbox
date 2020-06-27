#include <chrono>
#include <iostream>

using namespace std;

constexpr int matricLength = 1000;

static double sumRowColMatrix(const ulong matrix[matricLength][matricLength])
{
	auto start = chrono::high_resolution_clock::now();

	ulong sum = 0;
	for (size_t i = 0; i < matricLength; ++i)
	{
		for (size_t j = 0; j < matricLength; ++j)
		{
			sum += matrix[i][j];
		}
	}

	auto finish = chrono::high_resolution_clock::now();

	chrono::duration<double> elapsed = finish - start;
	return elapsed.count();
}

static double sumColRowMatrix(const ulong matrix[matricLength][matricLength])
{
	auto start = chrono::high_resolution_clock::now();

	ulong sum = 0;
	for (size_t i = 0; i < matricLength; ++i)
	{
		for (size_t j = 0; j < matricLength; ++j)
		{
			sum += matrix[j][i];
		}
	}

	auto finish = chrono::high_resolution_clock::now();

	chrono::duration<double> elapsed = finish - start;
	return elapsed.count();
}

static void compareSpeed(const int loopNum)
{
	ulong matrix[matricLength][matricLength];
	for (size_t i = 0; i < matricLength; ++i)
	{
		for (size_t j = 0; j < matricLength; ++j)
		{
			matrix[i][j] = i + j * matricLength;
		}
	}

	double rowColTime = 0.;
	double colRowTime = 0.;
	for (int i = 0; i < loopNum; ++i)
	{
		rowColTime += sumRowColMatrix(matrix);
		colRowTime += sumColRowMatrix(matrix);
	}

	cout << "Average for rowCol access: " << rowColTime / loopNum << "s" << endl;
	cout << "Average for colRow access: " << colRowTime / loopNum << "s" << endl;
}

int main()
{
	// When changing access pattern we can expect to see higher performance from the method that is benefitting from
	// cache hit, since when caching the CPU will also take the data surrounding the requested data.

	cout << "Comparing access time for matrices (row by row or column by column)" << endl;
	compareSpeed(100);

	/*
	Using perf tool I was able to compare the number of cache misses (by commenting the call to rowCol and colRow
	respectively).
	command: perf stat -d ./out/access_strategy
	result with only rowCol (colRow commented out): " 12 948 376      L1-dcache-load-misses"
	result with only colRow (rowCol commented out): "103 206 725      L1-dcache-load-misses"
	*/
}