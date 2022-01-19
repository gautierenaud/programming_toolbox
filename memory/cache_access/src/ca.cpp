// CLS is given by gcc at compile time
#define SM (CLS / sizeof(double))
#include <x86intrin.h>

#include "matrix_common.hpp"

extern double ret[n][n];
extern double mat1[n][n];
extern double mat2[n][n];

void cacheAlignedMult(double mat1[][n], double mat2[][n], double ret[][n])
{
	int iSM = (int)SM;

	for (int i = 0; i < n; i += iSM)
	{
		for (int j = 0; j < n; j += iSM)
		{
			for (int k = 0; k < n; k += iSM)
			{
				double *rret = &ret[i][j];
				double *rmat1 = &mat1[i][k];

				for (int i2 = 0; i2 < iSM; ++i2)
				{

					// Fetch the line of data from memory that contains address p to a location in the cache heirarchy
					// specified by the locality hint i. -> into stream buffer or equivalent
					_mm_prefetch(&rmat1[8], _MM_HINT_NTA);

					double *rmat2 = &mat2[k][j];

					for (int k2 = 0; k2 < iSM; ++k2)
					{
						/**
						 * Load a double-precision (64-bit) floating-point element from memory into the lower of dst,
						 * and zero the upper element. mem_addr does not need to be aligned on any particular boundary.
						 */
						__m128d m1d = _mm_load_sd(&rmat1[k2]);

						/**
						 * Unpack and interleave double-precision (64-bit) floating-point elements from the low half of
						 * a and b, and store the results in dst.
						 */
						m1d = _mm_unpacklo_pd(m1d, m1d);

						for (int j2 = 0; j2 < iSM; j2 += 2)
						{
							/**
							 * Load 128-bits (composed of 2 packed double-precision (64-bit) floating-point elements)
							 * from memory into dst. mem_addr must be aligned on a 16-byte boundary or a
							 * general-protection exception may be generated.
							 */
							__m128d m2 = _mm_load_pd(&rmat2[j2]);
							__m128d r2 = _mm_load_pd(&rret[j2]);

							_mm_store_pd(&rret[j2], _mm_add_pd(_mm_mul_pd(m2, m1d), r2));
						}
					}

					rmat2 += n;
				}

				rret += n;
				rmat1 += n;
			}
		}
	}
}

/* sample from tutorial (in C on intel)


int i, i2, j, j2, k, k2;
double *restrict rres;
double *restrict rmul1;
double *restrict rmul2;
for (i = 0; i < N; i += SM)
	for (j = 0; j < N; j += SM)
		for (k = 0; k < N; k += SM)
			for (i2 = 0, rres = &res[i][j], rmul1 = &mul1[i][k]; i2 < SM;
					++i2, rres += N, rmul1 += N)
			{
				_mm_prefetch (&rmul1[8], _MM_HINT_NTA); // NTA -> Non Temporal -> streaming loading buffers
				for (k2 = 0, rmul2 = &mul2[k][j]; k2 < SM; ++k2, rmul2 += N)
				{
					// loads a 64bit double into 128 bits, with upper 64bits are zeros, lower 64bits are values:
00...00ab...yz
					__m128d m1d = _mm_load_sd (&rmul1[k2]);
					// unpack & interleave double from lower halves of both -> ab..yzab..yz
					m1d = _mm_unpacklo_pd(m1d, m1d);
					for (j2 = 0; j2 < SM; j2 += 2)
					{
						__m128d m2 = _mm_load_pd (&rmul2[j2]);	// load 2 packed doubles-> a2b2..y2z2a3b3..y3z3
						__m128d r2 = _mm_load_pd (&rres[j2]);	// -> a4b4..y4z4a5b5..y5z5

						// _mm_mul_pd: Multiply packed double-precision (64-bit) floating-point elements in a and b, and
store the results in dst.
						//		-> value loaded into m1d is multiplied twice ? with 2 different values ?

						// _mm_add_pd add 2-packed doubles (do we need it ? I thought r2 was supposed to be empty...)

						_mm_store_pd (&rres[j2], _mm_add_pd (_mm_mul_pd (m2, m1d), r2));
					}
				}
			}


*/

int main()
{
	doMatrixCheck(cacheAlignedMult);

	return 0;
}