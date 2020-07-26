#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace std;
namespace fs = filesystem;

const fs::path outputFolder = "outputs";

// since it is a balanced two way merge, some parameters are fixed in advance
const int tapeNum = 4;
const int partitionNum = 2;

class TapeReader
{
  public:
	TapeReader(uint readLimit, fs::path tapePath) : m_readLimit(readLimit), m_isTapeLeft(true)
	{
		m_tapeInputStream.open(tapePath);
	}

	bool isTapeActive() { return m_isTapeLeft && getCount() < static_cast<int>(m_readLimit); }
	bool isTapeFinished() { return m_isTapeLeft; }
	int getCount() { return m_readCount; }
	void resetCount() { m_readCount = 0; }
	int readTape()
	{
		int val;
		if (m_tapeInputStream >> val)
		{
			m_readCount++;
		}
		else
		{
			m_isTapeLeft = false;
		}
		return val;
	}

  private:
	ifstream m_tapeInputStream;
	int m_readCount = -1;
	uint m_readLimit;
	bool m_isTapeLeft;
};

static tuple<string, int> parseArguments(int argc, char *argv[])
{
	if (argc != 3)
	{
		cout << "Wrong number of arguments." << endl;
		cout << "Usage: cmd <input_file> <memory_limit>" << endl;
		exit(1);
	}

	return {string(argv[1]), atoi(argv[2])};
}

static void cleanOutputFolder()
{
	filesystem::remove_all(outputFolder); // Deletes one or more files recursively.
	filesystem::create_directory(outputFolder);
}

static void appendSortedValuesToFile(const vector<int> &sortedValues, const string &filePath)
{
	ofstream outfile;
	outfile.open(filePath, ios::app);
	for (const auto &val : sortedValues)
	{
		outfile << val << endl;
	}
}

static void mergeTapes(const vector<fs::path> &tapePaths, uint runLegth, uint currentOutTapeDelta)
{
	uint currentInTapeDelta = 2 - currentOutTapeDelta;
	TapeReader firstTape(static_cast<uint>(runLegth), tapePaths[currentInTapeDelta]);
	TapeReader secondTape(static_cast<uint>(runLegth), tapePaths[currentInTapeDelta + 1]);

	uint currentOutTapeIndex = 0;
	ofstream currentOutTape;
	currentOutTape.open(tapePaths[currentOutTapeIndex + currentOutTapeDelta], ios::app);

	int firstVal = firstTape.readTape();
	int secondVal = secondTape.readTape();
	while (firstTape.isTapeFinished() || secondTape.isTapeFinished())
	{
		if (firstTape.isTapeActive() && !secondTape.isTapeActive())
		{
			currentOutTape << firstVal << endl;
			firstVal = firstTape.readTape();
		}
		else if (secondTape.isTapeActive() && !firstTape.isTapeActive())
		{
			currentOutTape << secondVal << endl;
			secondVal = secondTape.readTape();
		}
		else if (firstTape.isTapeActive() && secondTape.isTapeActive())
		{
			if (firstVal < secondVal)
			{
				currentOutTape << firstVal << endl;
				firstVal = firstTape.readTape();
			}
			else
			{
				currentOutTape << secondVal << endl;
				secondVal = secondTape.readTape();
			}
		}
		else
		{
			currentOutTape.close();
			currentOutTapeIndex ^= 1;

			currentOutTape.open(tapePaths[currentOutTapeIndex + currentOutTapeDelta], ios::app);

			firstTape.resetCount();
			secondTape.resetCount();
		}
	}
}

int main(int argc, char *argv[])
{
	string inputFile;
	uint memoryLimit;
	tie(inputFile, memoryLimit) = parseArguments(argc, argv);

	cleanOutputFolder();

	vector<fs::path> tapePaths;
	for (int i = 0; i < tapeNum; ++i)
	{
		fs::path tapePath = outputFolder;
		tapePath /= to_string(i) + "_tape";
		tapePaths.push_back(tapePath);
	}

	vector<int> internalStorage;
	internalStorage.reserve(memoryLimit);

	int val;
	ifstream infile(inputFile);
	uint currentTape = 0;

	uint totalLength = 0;
	// initial split into 2 tapes
	while (infile >> val)
	{
		internalStorage.push_back(val);
		++totalLength;

		if (internalStorage.size() > static_cast<size_t>(memoryLimit - 1))
		{
			sort(internalStorage.begin(), internalStorage.end());

			appendSortedValuesToFile(internalStorage, tapePaths[currentTape]);

			internalStorage.clear();
			currentTape = (currentTape + 1) % (partitionNum);
		}
	}

	uint mergeCounter = 0;
	uint currentRunLength = memoryLimit;
	uint outputDelta = 2;
	while (currentRunLength < totalLength)
	{
		fs::remove(tapePaths[outputDelta]);
		fs::remove(tapePaths[outputDelta + 1]);

		mergeTapes(tapePaths, currentRunLength, outputDelta);
		++mergeCounter;

		currentRunLength *= 2;
		outputDelta ^= 2;
	}

	cout << "Output at " << tapePaths[outputDelta ^ 2] << endl;
	cout << mergeCounter << " merges were done" << endl;

	return 0;
}
