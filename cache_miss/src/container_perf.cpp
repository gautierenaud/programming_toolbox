#include <array>
#include <chrono>
#include <deque>
#include <iostream>
#include <list>
#include <numeric>
#include <vector>

using namespace std;

template <class InputIt> void measureSumTime(InputIt first, InputIt last)
{
	auto start = chrono::high_resolution_clock::now();

	int sum = accumulate(first, last, 0);

	auto finish = chrono::high_resolution_clock::now();

	chrono::duration<double> elapsed = finish - start;
	cout << "Elapsed time: " << elapsed.count() << " s for summation (sum = " << sum << ")" << endl;
}

static void measureListSumTime(const int elementNum)
{
	list<int> intList;
	for (int i = 0; i < elementNum; ++i)
	{
		intList.push_back(i);
	}

	cout << "List:" << endl;
	measureSumTime(intList.begin(), intList.end());
}

static void measureVectorSumTime(const int elementNum)
{
	vector<int> intVector;
	for (int i = 0; i < elementNum; ++i)
	{
		intVector.push_back(i);
	}

	cout << "Vector:" << endl;
	measureSumTime(intVector.begin(), intVector.end());
}

static void measureDequeSumTime(const int elementNum)
{
	deque<int> intDeque;
	for (int i = 0; i < elementNum; ++i)
	{
		intDeque.push_back(i);
	}

	cout << "Deque:" << endl;
	measureSumTime(intDeque.begin(), intDeque.end());
}

int main()
{
	// this is a toy program using different containers.
	// continuous ones (such as vector) are supposed to be faster thanks to lower cache misses.
	const int elementNum = 1000000;

	measureListSumTime(elementNum);
	measureVectorSumTime(elementNum);
	measureDequeSumTime(elementNum);
}