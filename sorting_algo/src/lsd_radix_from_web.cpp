#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <algorithm>

using namespace std;

/**
 * @brief Get the Max object of a vector
 * 
 * @param vect vector from which to get the maximum value from
 * @return int max object
 */
static int getMax(const vector<int> &vect)
{
    return *max_element(begin(vect), end(vect));
}

static void countSort(vector<int> &vect, const int &nthDigit)
{

    vector<int> output(vect.size(), 0);
    int count[10]{0};

    for (const auto &num : vect)
    {
        count[(num / nthDigit) % 10]++;
    }

    for (int i = 1; i < 10; ++i)
    {
        count[i] += count[i - 1];
    }

    for (auto it = vect.rbegin(); it != vect.rend(); ++it)
    {
        int newIndex = (*it / nthDigit) % 10;
        output[count[newIndex] - 1] = *it;
        count[newIndex]--;
    }

    vect = output;
}

static void sort(vector<int> &listToSort)
{
    int maxNumber = getMax(listToSort);

    for (int nthDigit = 1; maxNumber / nthDigit > 0; nthDigit *= 10)
    {
        countSort(listToSort, nthDigit);
    }
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
