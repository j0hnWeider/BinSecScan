#ifndef ENTROPY_H
#define ENTROPY_H

#include <stddef.h>

// Calcula a entropia de Shannon de um buffer
double calculate_shannon_entropy(const unsigned char *data, size_t length);

#endif
