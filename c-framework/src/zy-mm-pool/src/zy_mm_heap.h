#ifndef _ZY_MM_HEAP_H_
#define _ZY_MM_HEAP_H_
#include "zy_mm_malloc.h"

zy_mm_mstate_t *zy_mm_init_malloc(void* addr_start, size_t size);

#endif