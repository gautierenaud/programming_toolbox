#include <chrono>
#include <iostream>
#include <vector>

using namespace std;

static vector<int> addVectors(const vector<int> &a, const vector<int> &b)
{
	vector<int> result(a.size(), 0);

	if (a.size() == b.size())
	{
		auto start = chrono::high_resolution_clock::now();

		for (size_t i = 0; i < a.size(); ++i)
		{
			result[i] = a[i] + b[i];
		}

		auto finish = chrono::high_resolution_clock::now();

		chrono::duration<double> elapsed = finish - start;
		cout << "Elapsed time: " << elapsed.count() << " s for addition" << endl;
	}

	return result;
}

static vector<int> createVector(const int &size)
{
	vector<int> result(size);
	for (int i = 0; i < size; ++i)
	{
		result[i] = i;
	}
	return result;
}

static void printVector(const vector<int> &v)
{
	for (const auto &val : v)
	{
		cout << val << ' ';
	}
	cout << endl;
}

int main()
{
	int size = 10000000;
	vector<int> a = createVector(size);
	vector<int> b = createVector(size);

	vector<int> c = addVectors(a, b);
	// printVector(c);
}
