#include <iostream>
#include <vector>

using namespace std;

static void addToPreviousVectorizable(vector<int> &a)
{
	for (size_t i = 5; i < a.size(); ++i)
	{
		a[i] += a[i - 4] + a[i - 5];
	}
}

static void addToPreviousUnvectorizable(vector<int> &a)
{
	for (size_t i = 5; i < a.size(); ++i)
	{
		a[i] += a[i - 4] + a[i - 5];
		a[i - 3] += a[i - 2];
	}
}

static void addToPreviousUnvectorizableSmall(vector<int> &a)
{
    cout << "Adding to previous small version (unvectorizable)" << endl;
	for (size_t i = 1; i < a.size(); ++i)
	{
		a[i] += a[i - 1];
	}
}

static void addToPreviousVectorizableSmall(vector<int> &a)
{
    cout << "Adding to previous small version (vectorizable)" << endl;
	for (size_t i = 3; i < a.size(); ++i)
	{
		a[i] += a[i - 3];
	}
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

    // call twice just to be sure to see it in objdump
	vector<int> a = createVector(size);
	addToPreviousVectorizable(a);
	addToPreviousVectorizable(a);

	vector<int> b = createVector(size);
    addToPreviousUnvectorizable(b);
    addToPreviousUnvectorizable(b);

	vector<int> c = createVector(size);
    addToPreviousUnvectorizableSmall(c);
    addToPreviousUnvectorizableSmall(c);

	vector<int> d = createVector(size);
    addToPreviousVectorizableSmall(d);
    addToPreviousVectorizableSmall(d);

	// printVector(a);
}
