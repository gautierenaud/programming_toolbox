#include "matrix_common.hpp"

extern double ret[n][n];
extern double mat1[n][n];
extern double mat2[n][n];

double transposed[n][n] __attribute__((aligned(64)));

void transposedMult(double mat1[][n], double mat2[][n], double ret[][n])
{
	// we can also use the transposed of the second matrix, which will be accessed sequentially
	createEmptyMatrix(transposed);
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
}

int main()
{
	doMatrixCheck(transposedMult);

	return 0;
}