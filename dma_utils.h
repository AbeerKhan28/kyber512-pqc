#ifndef DMA_UTILS_H
#define DMA_UTILS_H

#include <stdint.h>
#include "pico/stdlib.h"

// Initialize DMA for array copy
void dma_copy_init(void);
void dma_copy(int16_t *src,int16_t *dst,int size);
// Add these declarations
void dma_start_power_masking(void);
void dma_stop_power_masking(void);
#endif