#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <unistd.h>

using namespace std;

/**
 * Returns the memory usage in kb
 */
void processMemUsage(double& vmUsage, double& residentSet)
{
    vmUsage     = 0.0;
    residentSet = 0.0;

    // the two fields we want
    unsigned long vsize;
    long rss;
    {
        std::string ignore;
        std::ifstream ifs("/proc/self/stat", std::ios_base::in);
        ifs >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
            >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
            >> ignore >> ignore >> vsize >> rss;
    }

    long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    vmUsage = vsize / 1024.0;
    residentSet = rss * page_size_kb;
}

template<typename T>
vector<T> createVector(const size_t vectorSize) {
    vector<T> fillMe;
    for (int i = 0; i < vectorSize; ++i) {
        fillMe.push_back(T());
    }

    return fillMe;
}

template<typename T>
vector<vector<T>> getVmDiff(const size_t vectorSize, const int count=1) {
    cout << "Size: " << sizeof(T) << " bytes, assign " << count << " time" << endl;

    vector<vector<T>> result(count);

    long long elapsedTime = 0;
    double totVm = 0., totRss = 0.;

    for (int time = 0; time < count; ++time) {
        double startVm, startRss;
        processMemUsage(startVm, startRss);

        auto start = chrono::steady_clock::now();
        result.push_back(createVector<T>(vectorSize));
        auto end = chrono::steady_clock::now();

        double endVm, endRss;
        processMemUsage(endVm, endRss);

        elapsedTime += chrono::duration_cast<chrono::microseconds>(end - start).count();
        totVm += endVm - startVm;
        totRss = endRss - startRss;
    }

    cout << "Average time: "
        << elapsedTime / (double)count
        << " µs" << endl;

    cout << "Average VM: "
        << totVm / (double)count
        << " k" << endl;

    cout << "Average rss: "
        << totRss / (double)count
        << " k" << endl;

    return result;
}

// size: 16 bytes
struct ShortIntShortInt {
    short a;    // 2 bytes + 2 padding bytes
    int b;      // 4 bytes
    short c;    // 2 bytes + 2 padding bytes
    int d;      // 4 bytes
};

// size: 24 bytes
struct ShortIntShortDouble {
    short a;    // 2 bytes
    int b;      // 4 bytes + 2 padding bytes
    short c;    // 2 bytes + 6 padding bytes
    double d;   // 8 bytes
};

// size: 16 bytes
struct ShortShortIntDouble {
    short a;    // 2 bytes
    short b;    // 2 bytes
    int c;      // 4 bytes
    double d;   // 8 bytes
};

// size: 16 bytes
struct DoubleIntShortCharChar {
    double a;   // 8 bytes
    int b;      // 4 bytes
    short c;    // 2 bytes
    char d;     // 1 byte
    char e;     // 1 byte
};

// size: 32 bytes
struct CharDoubleCharIntShort {
    char a;     // 1 byte + 7 padding bytes
    double b;   // 8 bytes
    char c;     // 1 byte + 1 padding byte
    int d;      // 4 bytes
    short e;    // 2 bytes
};

int main(int argc, char *argv[]) {
    const size_t vectorSize = atoi(argv[1]);
    const size_t assignTime = atoi(argv[2]);

    cout << "ShortShortIntDouble:" << endl;
    auto case1 = getVmDiff<ShortShortIntDouble>(vectorSize, assignTime);
    cout << endl;

    cout << "ShortIntShortDouble:" << endl;
    auto case2 = getVmDiff<ShortIntShortDouble>(vectorSize, assignTime);
    cout << endl;

    cout << "ShortIntShortInt:" << endl; 
    auto case3 = getVmDiff<ShortIntShortInt>(vectorSize, assignTime);
    cout << endl;

    cout << "DoubleIntShortCharChar:" << endl; 
    auto case4 = getVmDiff<DoubleIntShortCharChar>(vectorSize, assignTime);
    cout << endl;
    
    cout << "CharDoubleCharIntShort:" << endl; 
    auto case5 = getVmDiff<CharDoubleCharIntShort>(vectorSize, assignTime);
    cout << endl;
}
