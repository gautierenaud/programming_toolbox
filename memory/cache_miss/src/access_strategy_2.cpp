/*
This one is made from [Memory part 5: What programmers can do](https://lwn.net/Articles/255364/)
It is quite similar to access_strategy.cpp, since both case compare cache miss with a matrix use case (this time a
multiplication)
*/

// CLS is given by gcc at compile time
#define SM (CLS / sizeof(int))

#include <chrono>
#include <iomanip> // for column alignement in the output
#include <iostream>

using namespace std;

constexpr int n = 1000;

int **createEmptyMatrix()
{
	int **ret = 0;
	ret = new int *[n];
	for (int i = 0; i < n; ++i)
	{
		ret[i] = new int[n];

		for (int j = 0; j < n; ++j)
		{
			ret[i][j] = 0;
		}
	}
	return ret;
}

int **createPrefilledMatrix()
{
	int **ret = 0;
	ret = new int *[n];
	for (int i = 0; i < n; ++i)
	{
		ret[i] = new int[n];

		for (int j = 0; j < n; ++j)
		{
			ret[i][j] = i * j;
		}
	}
	return ret;
}

int **straightForwardMult(int **mat1, int **mat2)
{
	int **ret = createEmptyMatrix();

	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			for (int k = 0; k < n; ++k)
			{
				ret[i][j] = mat1[i][k] * mat2[k][j];
			}
		}
	}

	return ret;
}

int **transposedMult(int **mat1, int **mat2)
{
	int **ret = createEmptyMatrix();

	// we can also use the transposed of the second matrix, which will be accessed sequentially
	int **transposed = createEmptyMatrix();
	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			transposed[i][j] = mat2[j][i];
		}
	}

	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			for (int k = 0; k < n; ++k)
			{
				ret[i][j] = mat1[i][k] * transposed[j][k];
			}
		}
	}

	return ret;
}

int **cacheAlignedMult(int **mat1, int **mat2)
{
	int **ret = createEmptyMatrix();

	for (int i = 0; i < n; i += SM)
	{
		for (int j = 0; j < n; j += SM)
		{
			for (int k = 0; k < n; k += SM)
			{
				// small optimisation for gcc in origin, don't know if they are still relevant
				int *rret = ret[i];
				int *rmat1 = mat1[i];

				for (int i2 = 0; i2 < SM; ++i2, rret += n, rmat1 += n)
				{
					int *rmat2 = mat2[k];

					for (int k2 = 0; k2 < SM; ++k2, rmat2 += n) {
						for (int j2 = 0; j2 < SM; ++j2) {
							rret[j2] += rmat1[k2] * rmat2[j2];
						}
					}
				}
			}
		}
	}

	return ret;
}

bool checkSame(int **mat1, int **mat2) {
	bool ret = true;
	
	for (int i = 0; i < n; ++i) {
		for (int j = 0; j < 0; j++) {
			ret &= mat1[i][j] == mat2[i][j];
		}
	}

	return ret;
}

int main()
{
	int **mat1 = createPrefilledMatrix();
	int **mat2 = createPrefilledMatrix();

	// Straight Forward (SF)
	auto startSF = chrono::high_resolution_clock::now();
	int **multSF = straightForwardMult(mat1, mat2);
	auto finishSF = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsedSF = finishSF - startSF;
	cout << left << setw(25) << "Straight Forward: " << elapsedSF.count() << " s" << endl;

	// Transposed (T)
	auto startT = chrono::high_resolution_clock::now();
	int **multT = straightForwardMult(mat1, mat2);
	auto finishT = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsedT = finishT - startT;
	cout << left << setw(25) << "Transposed: " << elapsedT.count() << " s" << endl;
	cout << "Is ok: " << checkSame(multSF, multT) << endl;

	// Cache Aligned (CA)
	auto startCA = chrono::high_resolution_clock::now();
	int **multCA = straightForwardMult(mat1, mat2);
	auto finishCA = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsedCA = finishCA - startCA;
	cout << left << setw(25) << "Cache Aligned: " << elapsedCA.count() << " s" << endl;
	cout << "Is ok: " << checkSame(multSF, multCA) << endl;

	return 0;
}