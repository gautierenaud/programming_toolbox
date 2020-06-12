#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>

using namespace std;

static void sort(vector<int> &listToSort)
{
    // do your thing
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
