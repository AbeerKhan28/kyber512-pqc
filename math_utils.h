#ifndef MATH_UTILS_H
#define MATH_UTILS_H

#include <stdint.h>

#define Q 3329
#define N 256  
#define K 2

#define USE_MONTGOMERY 0
int16_t montgomery_reduce(int32_t t);
int16_t mul_mod(int16_t a, int16_t b);


int16_t mod_q(int32_t x);
int16_t small_random(); // -1, 0, 1
void vector_add(int16_t *a, int16_t *b, int16_t *res, int size);
void vector_sub(int16_t *a, int16_t *b, int16_t *res, int size);
void vector_copy(int16_t *src, int16_t *dst, int size);

#endif
