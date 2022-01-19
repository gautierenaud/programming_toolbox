#pragma once

constexpr int n = 2;

void createEmptyMatrix(double mat[][n]);

void createPrefilledMatrix(double mat[][n]);

bool checkMatrix(double mat[][n]);

void doMatrixCheck(void (*function)(double mat1[][n], double mat2[][n], double ret[][n]));