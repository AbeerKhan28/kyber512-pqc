#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "math_utils.h"

void init_ntt(void);
void ntt(int16_t *a);
void intt(int16_t *a);
void poly_mul(int16_t *a, int16_t *b, int16_t *res);
void poly_basemul(int16_t *res, const int16_t *a_hat, const int16_t *b_hat);
void poly_basemul_acc(int16_t *acc, const int16_t *a_hat, const int16_t *b_hat);

#endif