#include <iostream>
#include <fstream>
#include <vector>

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

    sort(listToSort);

    printList(listToSort);
}