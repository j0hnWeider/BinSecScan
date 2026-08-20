#include "entropy.h"
#include <math.h>
#include <string.h>

double calculate_shannon_entropy(const unsigned char *data, size_t length) {
    if (length == 0) return 0.0;

    // Histograma de frequência para 256 possíveis valores de byte
    int freq[256];
    memset(freq, 0, sizeof(freq));

    for (size_t i = 0; i < length; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double inv_length = 1.0 / (double)length;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;

        double p = (double)freq[i] * inv_length;
        entropy -= p * log2(p);
    }

    return entropy;
}
