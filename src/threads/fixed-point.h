#ifndef PINTOS_25_FIXED_POINT_H
#define PINTOS_25_FIXED_POINT_H

#include <stdint.h>

#define P 17
#define Q 14
#define F (1<<Q)

#define CONVERT_N_TO_FIXED_POINT(n) (n*F)

#define CONVERT_X_TO_INTEGER_ROUND_TO_ZERO(x) (x/F)

#define CONVERT_X_TO_INTEGER_ROUND_TO_NEAREST(x) ( (x>=0) ? ((x + (F / 2)) / F) : ((x - (F / 2)) / F) )

#define ADD_X_Y(x, y) (x+y)

#define SUB_Y_FROM_X(x, y) (x-y)

#define ADD_X_N(x, n) (x + (n*F))

#define SUB_N_FROM_X(n, x) (x - (n*F))

#define MULT_X_Y(x, y) ((((int64_t) x) *y) / F)

#define MULT_X_N(x, n) (x*n)

#define DIV_X_BY_Y(x, y) ((((int64_t) x) * F) / y)

#define DIV_X_BY_N(x, n) (x/n)

#endif //PINTOS_25_FIXED_POINT_H


