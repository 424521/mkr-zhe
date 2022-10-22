#ifndef _ZY_MM_SLAB_H_
#define _ZY_MM_SLAB_H_
#include <stdint.h>
#include <sys/types.h>

#include "zy_mm_lock.h"

typedef struct zy_mm_slab_page_s zy_mm_slab_page_t;

struct zy_mm_slab_page_s {
    uintptr_t           slab;
    zy_mm_slab_page_t  *next;
    uintptr_t           prev;
};

typedef struct {
    uintptr_t           slab_max_size;
    uintptr_t           slab_exact_size;
    uintptr_t           slab_exact_shift;
    uintptr_t           pagesize;
    uintptr_t           pagesize_shift;
    uintptr_t           real_pages;

    size_t              min_size;
    size_t              min_shift;
	size_t              block_size;

    zy_mm_slab_page_t  *pages;
    zy_mm_slab_page_t   free;

    u_char              *start;
    u_char              *end;

	mutex_t		mutex;

    void                *addr;
} zy_mm_slab_pool_t;

typedef struct {
	size_t 			pool_size, used_size, used_pct;
	size_t			pages, free_page;
	size_t			p_small, p_exact, p_big, p_page; /* 四种slab占用的page数 */
	size_t			b_small, b_exact, b_big, b_page; /* 四种slab占用的byte数 */
	size_t			max_free_pages;					 /* 最大的连续可用page数 */
} zy_mm_slab_stat_t;

void zy_mm_slab_init(zy_mm_slab_pool_t *pool);
void *zy_mm_slab_alloc(void *pool, size_t size);
void *zy_mm_slab_alloc_locked(zy_mm_slab_pool_t *pool, size_t size);
void *zy_mm_slab_calloc(void *pool, size_t nmemb, size_t size);
void zy_mm_slab_free(void *pool, void *p);
void zy_mm_slab_free_locked(zy_mm_slab_pool_t *pool, void *p);

void zy_mm_slab_dummy_init(zy_mm_slab_pool_t *pool);
void zy_mm_slab_stat(zy_mm_slab_pool_t *pool, zy_mm_slab_stat_t *stat);

#endif /* _AHX_SLAB_H_INCLUDED_ */