#ifndef PADDING_H
#define PADDING_H

#include <sodium.h>
#include <stdint.h>

static inline int generate_padding(uint16_t pad_min, uint16_t pad_max, uint8_t *out, int out_cap)
{
    if (pad_max == 0) return 0;
    if (pad_min > pad_max) pad_min = pad_max;
    uint16_t range = pad_max - pad_min + 1;
    uint16_t pad_len = pad_min + (uint16_t)randombytes_uniform(range);
    if (pad_len > (uint16_t)out_cap) pad_len = (uint16_t)out_cap;
    randombytes_buf(out, pad_len);
    return (int)pad_len;
}

#endif