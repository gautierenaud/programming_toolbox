#include <iostream>
#include <x86intrin.h>

using namespace std;

void printDoubleDouble(__m128d d) { cout << d[0] << ", " << d[1] << endl; }

int main()
{
	double dArray[] __attribute__((aligned(64))) = {0, 1, 2, 3, 4242, 8, 9, 10, 11, 12, 13, 45, 45, 45, 45, 45, 45};

	// load 2 double values
	__m128d m1d = _mm_load_pd(dArray);
	printDoubleDouble(m1d);
	// 0, 1

	__m128d m2d = _mm_load_pd(&dArray[2]);
	printDoubleDouble(m2d);
	// 2, 3

	__m128d mult = _mm_mul_pd(m1d, m2d);
	printDoubleDouble(mult);
	// 0, 3

	// load 1 double value
	__m128d m3d = _mm_load_sd(&dArray[4]);
	printDoubleDouble(m3d);
	// 4242, 0

	__m128d add = _mm_add_pd(m3d, mult);
	printDoubleDouble(add);
	// 4242, 3

	_mm_store_pd(&dArray[0], add);
	for (const auto &val : dArray)
	{
		cout << val << " ";
	}
	cout << endl;
    // 4242 3 2 3 4242 ... (rest is filler to have enough space)

	return 0;
}