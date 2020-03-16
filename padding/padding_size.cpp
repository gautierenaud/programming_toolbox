#include <iostream>
#include <vector>

using namespace std;

// size: 24 bytes
struct IntDoubleInt {
    int a;      // IntIntDouble with below -> 8 bytes (+4 bytes of padding)
    double b;   // Biggest -> 8 bytes
    int c;      // IntIntDouble with above -> 8 bytes (+4 bytes of padding)
};

// size: 16 bytes
struct IntIntDouble {
    int a;      // Together with line below -> 8 bytes
    int b;
    double c;   // Biggest -> 8 bytes
};

// size: 8 bytes
struct IntShortChar {
    int a;      // 4 bytes
    short b;    // 2 bytes (together with char c -> 4 bytes)
    char c;     // 1 + 1 byte 
};

// size: 16 bytes
struct IntShortIntChar {
    int a;      // 4 bytes
    short b;    // 2 bytes + 2 padding bytes
    int c;      // 4 bytes
    char d;     // 1 bytes + 3 padding bytes
};

// size: 12 bytes
struct ShortCharIntInt {
    short a;    // 2 bytes
    char b;     // 1 bytes + 1 padding bytes
    int c;      // 4 bytes
    int d;      // 4 bytes
};

// size: 40 bytes
struct IntStructChar {
    int a;          // 4 bytes + 4 bytes
    IntDoubleInt b; // 24 bytes (longest: 8 bytes)
    char c;         // 1 bytes + 7 bytes
};

// size: 24 bytes
struct CharIntStruct {
    char a;         // 1 byte
    int b;          // 1 padding bytes (must start at even address) + 4 bytes + 3 padding bytes
    IntIntDouble c; // 16 bytes (4 + 4 + 8)
};

// size: 16 bytes
struct DoubleStruct {
    double a;       // 8 bytes
    struct ShortShort {
        short a;    // 2 bytes
        short b;    // 2 bytes
    };
    ShortShort b;   // 4 bytes + 4 padding bytes
};

// size: 16 bytes
struct IntBigStruct {
    int a;          // 4 bytes
    struct  ShortShortShortShortShort {
        short a;    // 2 bytes
        short b;    // 2 bytes
        short c;    // 2 bytes
        short d;    // 2 bytes
        short e;    // 2 bytes
    };
    ShortShortShortShortShort b;   // 10 bytes + 2 padding bytes because of the int at the beginning
};

template<typename T>
size_t vectorSize(const vector<T> &v) {
    return sizeof(vector<T>) + v.size() * sizeof(T);
}

int main() {
    cout << "# Size of different data structures" << endl;

    IntDoubleInt bad;
    cout << "[IntDoubleInt] With padding (wrong order of variable declaration)" << endl;
    cout << sizeof(bad) << endl;

    IntIntDouble good;
    cout << "[IntIntDouble] Without padding (good order of variable declaration)" << endl;
    cout << sizeof(good) << endl;

    IntShortChar intShortChar;
    cout << "[IntShortChar] With some padding" << endl;
    cout << sizeof(intShortChar) << endl;

    IntShortIntChar intShortIntChar;
    cout << "[IntShortIntChar] With some padding" << endl;
    cout << sizeof(intShortIntChar) << endl;

    ShortCharIntInt shortCharIntInt;
    cout << "[ShortCharIntInt] With some padding (optimized compared to IntShortIntChar)" << endl;
    cout << sizeof(shortCharIntInt) << endl;

    IntStructChar intStructChar;
    cout << "[IntStructChar] With some padding (not optimized)" << endl;
    cout << sizeof(intStructChar) << endl;

    CharIntStruct charIntStruct;
    cout << "[CharIntStruct] With some padding (optimized)" << endl;
    cout << sizeof(charIntStruct) << endl;

    DoubleStruct doubleStruct;
    cout << "[DoubleStruct]" << endl;
    cout << sizeof(doubleStruct) << endl;

    IntBigStruct intBigStruct;
    cout << "[IntBigStruct]" << endl;
    cout << sizeof(intBigStruct) << endl;

    cout << endl;
}
