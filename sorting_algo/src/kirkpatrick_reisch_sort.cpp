#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace std;

/**
 * @brief a trie is represented as a map with its key as the top half, then a {parent key, list of children} paired
 * value
 */
typedef unordered_map<int, vector<int>> trie;

/**
 * @brief A splitNum is a number cut in half. e.g 170 -> {1, 70}; 5502 -> {55, 2}
 */
typedef pair<int, int> splitNum;

/**
 * @brief Get the Max object of a vector
 *
 * @param vect vector from which to get the maximum value from
 * @return int max object
 */
static int getMax(const vector<int> &vect) { return *max_element(begin(vect), end(vect)); }

static trie buildTrie(const vector<int> &listToSort, const int &divider)
{
	trie resultTrie;

	for (const auto &num : listToSort)
	{
		int newTop = num / divider;
		int newBottom = num - newTop * divider;

		if (resultTrie.contains(newTop))
		{
			resultTrie[newTop].push_back(newBottom);
			if (resultTrie[newTop][0] > newBottom)
			{
				swap(resultTrie[newTop].front(), resultTrie[newTop].back());
			}
		}
		else
		{
			resultTrie[newTop].push_back(newBottom);
		}
	}

	return resultTrie;
}

static void writeSortedList(const trie &trie, const vector<int> &bucketOrder, const int &divider, vector<int> &destList)
{
	int insertIndex = 0;

	for (const auto &bucketNum : bucketOrder)
	{
		for (const auto &val : trie.at(bucketNum))
		{
			int insertVal = bucketNum * divider + val;
			destList[insertIndex] = insertVal;
			insertIndex++;
		}
	}
}

/**
 * @brief Count sort that will only work with single digit numbers
 *
 * @param vect
 */
static void countSortLastDigit(vector<int> &vect)
{
	vector<int> buffer(vect.size(), 0);
	int count[10]{0};

	for (const auto &num : vect)
	{
		count[num % 10]++;
	}

	for (int i = 1; i < 10; ++i)
	{
		count[i] += count[i - 1];
	}

	for (auto it = vect.rbegin(); it != vect.rend(); ++it)
	{
		int newIndex = *it % 10;
		buffer[count[newIndex] - 1] = *it;
		count[newIndex]--;
	}

	vect.swap(buffer);
}

static void recursiveSort(vector<int> &listToSort, const int &exp)
{
	if (listToSort.size() < 2)
	{
		return;
	}

	if (exp == 1)
	{
		countSortLastDigit(listToSort);
	}
	else
	{
		// recursive call to sort with half smaller items
		int newExp = static_cast<int>(ceil(exp / 2.));
		int divider = static_cast<int>(pow(10, newExp));

		// create a 2 level trie with half of a number for each level. e.g. 1234 -> 12 & 34
		auto trie = buildTrie(listToSort, divider);

		vector<int> topToSort;
		topToSort.reserve(trie.size());
		for (auto &[top, bottoms] : trie)
		{
			topToSort.push_back(top);

			vector<int> bottomToSort(next(bottoms.begin()), bottoms.end());
			recursiveSort(bottomToSort, newExp);

			bottoms.erase(next(bottoms.begin()), bottoms.end());
			bottoms.insert(next(bottoms.begin()), make_move_iterator(bottomToSort.begin()),
						   make_move_iterator(bottomToSort.end()));
		}

		recursiveSort(topToSort, newExp);

		writeSortedList(trie, topToSort, divider, listToSort);
	}
}

static void sort(vector<int> &listToSort)
{
	int maxElem = getMax(listToSort);
	int exp = static_cast<int>(to_string(maxElem).length());

	recursiveSort(listToSort, exp);
}

/**
 * @brief Parse arguments from the command line
 *
 * @param argc number of args
 * @param argv arguments
 * @return string path to the input file containing the numbers to sort
 */
static string parseArguments(int argc, char *argv[])
{
	if (argc != 2)
	{
		cout << "Wrong number of arguments." << endl;
		cout << "Usage: cmd <input_file>" << endl;
		exit(1);
	}

	string inputFilePath = string(argv[1]);
	return inputFilePath;
}

/**
 * @brief Read input file into vector of integer. We expect one integer per line.
 *
 * @param inputFilePath path to the input file
 * @return vector<int> list contained in the file
 */
static vector<int> readInputList(const string &inputFilePath)
{
	vector<int> result;

	ifstream inputFile(inputFilePath);
	if (inputFile.is_open())
	{
		string line;
		while (getline(inputFile, line))
		{
			result.push_back(stoi(line));
		}
		inputFile.close();
	}

	return result;
}

/**
 * @brief Write sorted list into file
 *
 * @param sortedList list to write in file
 */
static void writeSortedList(const vector<int> &sortedList)
{
	ofstream outputFile("out.txt");
	if (outputFile.is_open())
	{
		uint bufferLimit = 1000000;
		string buffer;
		buffer.reserve(bufferLimit);

		for (const auto &num : sortedList)
		{
			if (buffer.length() + sizeof(num) + 1 >= bufferLimit)
			{
				outputFile << buffer;
				buffer.resize(0);
			}

			buffer.append(to_string(num));
			buffer.append(1, '\n');
		}

		if (buffer.length() > 0)
		{
			outputFile << buffer;
		}

		outputFile.close();
	}
}

int main(int argc, char *argv[])
{
	string inputFilePath = parseArguments(argc, argv);
	vector<int> listToSort = readInputList(inputFilePath);

	auto start = chrono::high_resolution_clock::now();
	sort(listToSort);
	auto finish = chrono::high_resolution_clock::now();

	chrono::duration<double> elapsed = finish - start;
	cout << "Elapsed time: " << elapsed.count() << " s" << endl;

	writeSortedList(listToSort);
}
