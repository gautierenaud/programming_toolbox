#include "matrix_common.hpp"

// these are defined in matrice_common.cpp
extern double ret[n][n];
extern double mat1[n][n];
extern double mat2[n][n];

void straightForwardMult(double mat1[][n], double mat2[][n], double ret[][n])
{
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
}

int main()
{
	doMatrixCheck(straightForwardMult);

	return 0;
}