#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <cmath>
#include <map>

using namespace std;

int getNthDigit(const int num, const int n)
{
    return (int)(num / pow(10, n)) % 10;
}

static void sort(vector<int> &listToSort)
{
    map<int, vector<int>> buckets;

    for (const auto &num : listToSort)
    {
        int digit = getNthDigit(num, 0);
        buckets[digit].push_back(num);
    }

    for (int i = 1; i < (int)log10(listToSort.size()); ++i)
    {
        map<int, vector<int>> newBuckets;

        for (const auto &[digit, nums] : buckets)
        {
            for (const auto &num : nums)
            {
                int newDigit = getNthDigit(num, i);
                newBuckets[newDigit].push_back(num);
            }
        }

        buckets = newBuckets;
    }

    vector<int> result;
    for (const auto &[digit, nums] : buckets)
    {
        result.reserve(result.size() + distance(nums.begin(), nums.end()));
        result.insert(result.end(), nums.begin(), nums.end());
    }

    listToSort = result;
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
        for (const auto &num : sortedList)
        {
            outputFile << num << endl;
        }

        outputFile.close();
    }
}

/**
 * @brief Print the content of a vector
 * 
 * @param list vector to print
 */
void printList(const vector<int> &list)
{
    for (const auto &i : list)
    {
        cout << i << endl;
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