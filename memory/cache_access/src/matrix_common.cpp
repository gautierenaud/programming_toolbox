#include <chrono>
#include <iostream>

#include "matrix_common.hpp"

using namespace std;

double ret[n][n] __attribute__((aligned(64)));
double mat1[n][n] __attribute__((aligned(64)));
double mat2[n][n] __attribute__((aligned(64)));

void createEmptyMatrix(double mat[][n])
{
	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			mat[i][j] = 0.;
		}
	}
}

void createPrefilledMatrix(double mat[][n])
{
	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			mat[i][j] = i * j;
		}
	}
}

double checkRet[n][n] __attribute__((aligned(64)));
double checkMat1[n][n] __attribute__((aligned(64)));
double checkMat2[n][n] __attribute__((aligned(64)));

// same implementation as straight forward approach
void rightAnswerMatrix(double mat1[][n], double mat2[][n], double ret[][n])
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

bool checkMatrix(double mat[][n])
{
	createPrefilledMatrix(checkMat1);
	createPrefilledMatrix(checkMat2);
	createEmptyMatrix(checkRet);

	rightAnswerMatrix(checkMat1, checkMat2, checkRet);

	for (int i = 0; i < n; ++i)
	{
		for (int j = 0; j < n; ++j)
		{
			for (int k = 0; k < n; ++k)
			{
				if (checkRet[i][j] != mat[i][j]) {
					cout << "difference at i:" << i << ", j:" << j << endl;
					cout << "right value:" << checkRet[i][j] << endl;
					cout << "you gave:" << mat[i][j] << endl;
					return false;
				}
			}
		}
	}

	return true;
}

typedef void (* matrixMultFunc)(double mat1[][n], double mat2[][n], double ret[][n]);

void doMatrixCheck(matrixMultFunc funcToCheck) {
	createPrefilledMatrix(mat1);
	createPrefilledMatrix(mat2);
	createEmptyMatrix(ret);

	auto start = chrono::high_resolution_clock::now();
	funcToCheck(mat1, mat2, ret);
	auto finish = chrono::high_resolution_clock::now();
	chrono::duration<double> elapsed = finish - start;
	cout << elapsed.count() << " s" << endl;

	if (checkMatrix(ret)) {
		cout << "true" << endl;
	} else {
		cout << "false" << endl;
	}
}