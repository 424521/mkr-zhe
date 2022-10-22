
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>


#include "zy_mm_slab.h"
#include "zy_mm_log.h"

#define ZY_MM_SLAB_PAGE_MASK   3
#define ZY_MM_SLAB_PAGE        0
#define ZY_MM_SLAB_BIG         1
#define ZY_MM_SLAB_EXACT       2
#define ZY_MM_SLAB_SMALL       3

/* TODO */
#define ZY_MM_PTR_SIZE 8

#if (ZY_MM_PTR_SIZE == 4)

#define ZY_MM_SLAB_PAGE_FREE   0
#define ZY_MM_SLAB_PAGE_BUSY   0xffffffff
#define ZY_MM_SLAB_PAGE_START  0x80000000

#define ZY_MM_SLAB_SHIFT_MASK  0x0000000f
#define ZY_MM_SLAB_MAP_MASK    0xffff0000
#define ZY_MM_SLAB_MAP_SHIFT   16

#define ZY_MM_SLAB_BUSY        0xffffffff

#else /* (ZY_MM_PTR_SIZE == 8) */

#define ZY_MM_SLAB_PAGE_FREE   0
#define ZY_MM_SLAB_PAGE_BUSY   0xffffffffffffffff
#define ZY_MM_SLAB_PAGE_START  0x8000000000000000

#define ZY_MM_SLAB_SHIFT_MASK  0x000000000000000f
#define ZY_MM_SLAB_MAP_MASK    0xffffffff00000000
#define ZY_MM_SLAB_MAP_SHIFT   32

#define ZY_MM_SLAB_BUSY        0xffffffffffffffff

#endif


#if (ZY_MM_DEBUG_MALLOC)

#define zy_mm_slab_junk(p, size)     zy_mm_memset(p, 0xA5, size)

#else

#define zy_mm_slab_junk(p, size)

#endif

#define zy_mm_align_ptr(p, a)													 \
	(u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


static zy_mm_slab_page_t *zy_mm_slab_alloc_pages(zy_mm_slab_pool_t *pool,
    uint32_t pages);
static void zy_mm_slab_free_pages(zy_mm_slab_pool_t *pool, zy_mm_slab_page_t *page,
    uint32_t pages);

#ifdef PAGE_MERGE
static zy_mm_int_t zy_mm_slab_empty(zy_mm_slab_pool_t *pool, zy_mm_slab_page_t *page);
#endif

void
zy_mm_slab_init(zy_mm_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    uint32_t        i, n, pages;
    zy_mm_slab_page_t  *slots;

	mutex_init(&pool->mutex);
	/*pagesize*/
	pool->pagesize = getpagesize();
	for (n = pool->pagesize, pool->pagesize_shift = 0;
			n >>= 1; pool->pagesize_shift++) { /* void */ }

    /* STUB */
    if (pool->slab_max_size == 0) {
        pool->slab_max_size = pool->pagesize / 2;
        pool->slab_exact_size = pool->pagesize / (8 * sizeof(uintptr_t));
        for (n = pool->slab_exact_size; n >>= 1; pool->slab_exact_shift++) {
            /* void */
        }
    }

    pool->min_size = 1 << pool->min_shift;

    p = (u_char *) pool + sizeof(zy_mm_slab_pool_t);
    slots = (zy_mm_slab_page_t *) p;

    n = pool->pagesize_shift - pool->min_shift;
    for (i = 0; i < n; i++) {
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(zy_mm_slab_page_t);

    size = pool->end - p;
    zy_mm_slab_junk(p, size);

    pages = (uint32_t) (size / (pool->pagesize + sizeof(zy_mm_slab_page_t)));

    memset(p, 0, pages * sizeof(zy_mm_slab_page_t));

    pool->pages = (zy_mm_slab_page_t *) p;

    pool->free.prev = 0;
    pool->free.next = (zy_mm_slab_page_t *) p;

    pool->pages->slab = pages;
    pool->pages->next = &pool->free;
    pool->pages->prev = (uintptr_t) &pool->free;

    pool->start = (u_char *)
                  zy_mm_align_ptr((uintptr_t) p + pages * sizeof(zy_mm_slab_page_t),
                                 pool->pagesize);

	pool->real_pages = (pool->end - pool->start) / pool->pagesize;
	pool->pages->slab = pool->real_pages;
}


void *
zy_mm_slab_alloc(void *pool, size_t size)
{
    void  *p;
    zy_mm_slab_pool_t *pool1;

    pool1 = (zy_mm_slab_pool_t *)pool;

    mutex_lock(&pool1->mutex);

    p = zy_mm_slab_alloc_locked(pool1, size);

    mutex_unlock(&pool1->mutex);

    return p;
}


void *
zy_mm_slab_alloc_locked(zy_mm_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, n, m, mask, *bitmap;
    uint32_t        i, slot, shift, map;
    zy_mm_slab_page_t  *page, *prev, *slots;

    if (size >= pool->slab_max_size) {

		// zy_mm_dbg("slab, alloc: %zu\n", size);

        page = zy_mm_slab_alloc_pages(pool, (size >> pool->pagesize_shift)
                                          + ((size % pool->pagesize) ? 1 : 0));
        if (page) {
            p = (page - pool->pages) << pool->pagesize_shift;
            p += (uintptr_t) pool->start;

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        size = pool->min_size;
        shift = pool->min_shift;
        slot = 0;
    }

    slots = (zy_mm_slab_page_t *) ((u_char *) pool + sizeof(zy_mm_slab_pool_t));
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < pool->slab_exact_shift) {

            do {
                p = (page - pool->pages) << pool->pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + p);

                map = (1 << (pool->pagesize_shift - shift))
                          / (sizeof(uintptr_t) * 8);

                for (n = 0; n < map; n++) {

                    if (bitmap[n] != ZY_MM_SLAB_BUSY) {

                        for (m = 1, i = 0; m; m <<= 1, i++) {
                            if ((bitmap[n] & m)) {
                                continue;
                            }

                            bitmap[n] |= m;

                            i = ((n * sizeof(uintptr_t) * 8) << shift)
                                + (i << shift);

                            if (bitmap[n] == ZY_MM_SLAB_BUSY) {
                                for (n = n + 1; n < map; n++) {
                                     if (bitmap[n] != ZY_MM_SLAB_BUSY) {
                                         p = (uintptr_t) bitmap + i;

                                         goto done;
                                     }
                                }

                                prev = (zy_mm_slab_page_t *)
                                            (page->prev & ~ZY_MM_SLAB_PAGE_MASK);
                                prev->next = page->next;
                                page->next->prev = page->prev;

                                page->next = NULL;
                                page->prev = ZY_MM_SLAB_SMALL;
                            }

                            p = (uintptr_t) bitmap + i;

                            goto done;
                        }
                    }
                }

                page = page->next;

            } while (page);

        } else if (shift == pool->slab_exact_shift) {

            do {
                if (page->slab != ZY_MM_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if (page->slab == ZY_MM_SLAB_BUSY) {
                            prev = (zy_mm_slab_page_t *)
                                            (page->prev & ~ZY_MM_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = ZY_MM_SLAB_EXACT;
                        }

                        p = (page - pool->pages) << pool->pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);

        } else { /* shift > pool->slab_exact_shift */

            n = pool->pagesize_shift - (page->slab & ZY_MM_SLAB_SHIFT_MASK);
            n = 1 << n;
            n = ((uintptr_t) 1 << n) - 1;
            mask = n << ZY_MM_SLAB_MAP_SHIFT;

            do {
                if ((page->slab & ZY_MM_SLAB_MAP_MASK) != mask) {

                    for (m = (uintptr_t) 1 << ZY_MM_SLAB_MAP_SHIFT, i = 0;
                         m & mask;
                         m <<= 1, i++)
                    {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if ((page->slab & ZY_MM_SLAB_MAP_MASK) == mask) {
                            prev = (zy_mm_slab_page_t *)
                                            (page->prev & ~ZY_MM_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = ZY_MM_SLAB_BIG;
                        }

                        p = (page - pool->pages) << pool->pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);
        }
    }

    page = zy_mm_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < pool->slab_exact_shift) {
            p = (page - pool->pages) << pool->pagesize_shift;
            bitmap = (uintptr_t *) (pool->start + p);

            s = 1 << shift;
            n = (1 << (pool->pagesize_shift - shift)) / 8 / s;

            if (n == 0) {
                n = 1;
            }

            bitmap[0] = (2 << n) - 1;

            map = (1 << (pool->pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (i = 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_SMALL;

            slots[slot].next = page;

            p = ((page - pool->pages) << pool->pagesize_shift) + s * n;
            p += (uintptr_t) pool->start;

            goto done;

        } else if (shift == pool->slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_EXACT;

            slots[slot].next = page;

            p = (page - pool->pages) << pool->pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;

        } else { /* shift > pool->slab_exact_shift */

            page->slab = ((uintptr_t) 1 << ZY_MM_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_BIG;

            slots[slot].next = page;

            p = (page - pool->pages) << pool->pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;
        }
    }

    p = 0;

done:

    // zy_mm_dbg("slab, alloc: %p\n", (void *)p);

    return (void *) p;
}


void *
zy_mm_slab_calloc(void *pool, size_t nmemb, size_t size)
{
    void  *p;
    zy_mm_slab_pool_t *pool1;

    size = nmemb * size;
    pool1 = (zy_mm_slab_pool_t *)pool;

    mutex_lock(&pool1->mutex);

    p = zy_mm_slab_alloc_locked(pool1, size);

    mutex_unlock(&pool1->mutex);

    return p;
}

void
zy_mm_slab_free(void *pool, void *p)
{
    zy_mm_slab_pool_t *pool1;

    pool1 = (zy_mm_slab_pool_t *)pool;

    mutex_lock(&pool1->mutex);

    zy_mm_slab_free_locked(pool1, p);

    mutex_unlock(&pool1->mutex);
}


void
zy_mm_slab_free_locked(zy_mm_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    uint32_t        n, type, slot, shift, map;
    zy_mm_slab_page_t  *slots, *page;

    // zy_mm_dbg("slab, free: %p\n", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        //zy_mm_error("slab, mem free p[%p] outside of pool[%p], cpu[%d]\n", p, pool, current_cpu);
        zy_mm_error("slab, mem free p[%p] outside of pool[%p]\n", p, pool);
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> pool->pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = page->prev & ZY_MM_SLAB_PAGE_MASK;

    switch (type) {

    case ZY_MM_SLAB_SMALL:

        shift = slab & ZY_MM_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (pool->pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n & (sizeof(uintptr_t) * 8 - 1));
        n /= (sizeof(uintptr_t) * 8);
        bitmap = (uintptr_t *) ((uintptr_t) p & ~(pool->pagesize - 1));

        if (bitmap[n] & m) {

            if (page->next == NULL) {
                slots = (zy_mm_slab_page_t *)
                                   ((u_char *) pool + sizeof(zy_mm_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | ZY_MM_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (1 << (pool->pagesize_shift - shift)) / 8 / (1 << shift);

            if (n == 0) {
                n = 1;
            }

            if (bitmap[0] & ~(((uintptr_t) 1 << n) - 1)) {
                goto done;
            }

            map = (1 << (pool->pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (n = 1; n < map; n++) {
                if (bitmap[n]) {
                    goto done;
                }
            }

            zy_mm_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case ZY_MM_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (pool->pagesize - 1)) >> pool->slab_exact_shift);
        size = pool->slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            if (slab == ZY_MM_SLAB_BUSY) {
                slots = (zy_mm_slab_page_t *)
                                   ((u_char *) pool + sizeof(zy_mm_slab_pool_t));
                slot = pool->slab_exact_shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | ZY_MM_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            zy_mm_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case ZY_MM_SLAB_BIG:

        shift = slab & ZY_MM_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (pool->pagesize - 1)) >> shift)
                              + ZY_MM_SLAB_MAP_SHIFT);

        if (slab & m) {

            if (page->next == NULL) {
                slots = (zy_mm_slab_page_t *)
                                   ((u_char *) pool + sizeof(zy_mm_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | ZY_MM_SLAB_BIG;
                page->next->prev = (uintptr_t) page | ZY_MM_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & ZY_MM_SLAB_MAP_MASK) {
                goto done;
            }

            zy_mm_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case ZY_MM_SLAB_PAGE:

        if ((uintptr_t) p & (pool->pagesize - 1)) {
            goto wrong_chunk;
        }

		if (slab == ZY_MM_SLAB_PAGE_FREE) {
			zy_mm_error("slab, mm freee page is already free\n");
			goto fail;
        }

		if (slab == ZY_MM_SLAB_PAGE_BUSY) {
			zy_mm_error("slab, mm freee pointer to wrong page\n");
			goto fail;
        }

        n = ((u_char *) p - pool->start) >> pool->pagesize_shift;
        size = slab & ~ZY_MM_SLAB_PAGE_START;

        zy_mm_slab_free_pages(pool, &pool->pages[n], size);

        zy_mm_slab_junk(p, size << pool->pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    zy_mm_slab_junk(p, size);

    return;

wrong_chunk:

	zy_mm_error("slab, mm freee pointer to wrong chunk\n");

    goto fail;

chunk_already_free:

	zy_mm_error("slab, mm freee chunk is already free\n");

fail:

    return;
}


static zy_mm_slab_page_t *
zy_mm_slab_alloc_pages(zy_mm_slab_pool_t *pool, uint32_t pages)
{
    zy_mm_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (zy_mm_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (zy_mm_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | ZY_MM_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = ZY_MM_SLAB_PAGE;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = ZY_MM_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = ZY_MM_SLAB_PAGE;
                p++;
            }

            return page;
        }
	}
    //zy_mm_error("slab, pool[%p] alloc pages[%lu] failed, cpu[%d] no memory.\n", pool, pages, current_cpu);
    zy_mm_error("slab, pool[%p] alloc pages[%u] failed, no memory.\n", pool, pages);

    return NULL;
}

static void
zy_mm_slab_free_pages(zy_mm_slab_pool_t *pool, zy_mm_slab_page_t *page,
    uint32_t pages)
{
    zy_mm_slab_page_t  *prev;

	if (pages > 1) {
		memset(&page[1], 0, (pages - 1)* sizeof(zy_mm_slab_page_t));
	}

    if (page->next) {
        prev = (zy_mm_slab_page_t *) (page->prev & ~ZY_MM_SLAB_PAGE_MASK);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

	page->slab = pages;
	page->prev = (uintptr_t) &pool->free;
	page->next = pool->free.next;
	page->next->prev = (uintptr_t) page;

	pool->free.next = page;

#ifdef PAGE_MERGE
	if (pool->pages != page) {
		prev = page - 1;
		if (zy_mm_slab_empty(pool, prev)) {
			for (; prev >= pool->pages; prev--) {
				if (prev->slab != 0)
				{
					pool->free.next = page->next;
					page->next->prev = (uintptr_t) &pool->free;

					prev->slab += pages;
					zy_mm_memzero(page, sizeof(zy_mm_slab_page_t));

					page = prev;

					break;
				}
			}
		}
	}

	if ((page - pool->pages + page->slab) < pool->real_pages) {
		next = page + page->slab;
		if (zy_mm_slab_empty(pool, next))
		{
			prev = (zy_mm_slab_page_t *) (next->prev);
			prev->next = next->next;
			next->next->prev = next->prev;

			page->slab += next->slab;
			zy_mm_memzero(next, sizeof(zy_mm_slab_page_t));
		}
	}

#endif
}

void
zy_mm_slab_dummy_init(zy_mm_slab_pool_t *pool)
{
    uint32_t n;

	pool->pagesize = getpagesize();
	for (n = pool->pagesize, pool->pagesize_shift = 0;
			n >>= 1; pool->pagesize_shift++) { /* void */ }

    if (pool->slab_max_size == 0) {
        pool->slab_max_size = pool->pagesize / 2;
        pool->slab_exact_size = pool->pagesize / (8 * sizeof(uintptr_t));
        for (n = pool->slab_exact_size; n >>= 1; pool->slab_exact_shift++) {
            /* void */
        }
    }
}

void
zy_mm_slab_stat(zy_mm_slab_pool_t *pool, zy_mm_slab_stat_t *stat)
{
	uintptr_t 			m, n, mask, slab;
	uintptr_t 			*bitmap;
	uint32_t 			i, j, map, type, obj_size;
	zy_mm_slab_page_t 	*page;

	memset(stat, 0, sizeof(zy_mm_slab_stat_t));

	page = pool->pages;
 	stat->pages = (pool->end - pool->start) / pool->pagesize;;

	for (i = 0; i < stat->pages; i++)
	{
		slab = page->slab;
		type = page->prev & ZY_MM_SLAB_PAGE_MASK;

		switch (type) {

			case ZY_MM_SLAB_SMALL:

				n = (page - pool->pages) << pool->pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + n);

				obj_size = 1 << slab;
                map = (1 << (pool->pagesize_shift - slab))
                          / (sizeof(uintptr_t) * 8);

				for (j = 0; j < map; j++) {
					for (m = 1 ; m; m <<= 1) {
						if ((bitmap[j] & m)) {
							stat->used_size += obj_size;
							stat->b_small   += obj_size;
						}

					}
				}

				stat->p_small++;

				break;

			case ZY_MM_SLAB_EXACT:

				if (slab == ZY_MM_SLAB_BUSY) {
					stat->used_size += sizeof(uintptr_t) * 8 * pool->slab_exact_size;
					stat->b_exact   += sizeof(uintptr_t) * 8 * pool->slab_exact_size;
				}
				else {
					for (m = 1; m; m <<= 1) {
						if (slab & m) {
							stat->used_size += pool->slab_exact_size;
							stat->b_exact    += pool->slab_exact_size;
						}
					}
				}

				stat->p_exact++;

				break;

			case ZY_MM_SLAB_BIG:

				j = pool->pagesize_shift - (slab & ZY_MM_SLAB_SHIFT_MASK);
				j = 1 << j;
				j = ((uintptr_t) 1 << j) - 1;
				mask = j << ZY_MM_SLAB_MAP_SHIFT;
				obj_size = 1 << (slab & ZY_MM_SLAB_SHIFT_MASK);

				for (m = (uintptr_t) 1 << ZY_MM_SLAB_MAP_SHIFT; m & mask; m <<= 1)
				{
					if ((page->slab & m)) {
						stat->used_size += obj_size;
						stat->b_big     += obj_size;
					}
				}

				stat->p_big++;

				break;

			case ZY_MM_SLAB_PAGE:

				if (page->prev == ZY_MM_SLAB_PAGE) {
					slab 			=  slab & ~ZY_MM_SLAB_PAGE_START;
					stat->used_size += slab * pool->pagesize;
					stat->b_page    += slab * pool->pagesize;
					stat->p_page    += slab;

					i += (slab - 1);

					break;
				}

			default:

				if (slab  > stat->max_free_pages) {
					stat->max_free_pages = page->slab;
				}

				stat->free_page += slab;

				i += (slab - 1);

				break;
		}

		page = pool->pages + i + 1;
	}

	stat->pool_size = pool->end - pool->start;
	stat->used_pct = stat->used_size * 100 / stat->pool_size;

	zy_mm_info("pool_size : %zu bytes\n",	stat->pool_size);
	zy_mm_info("used_size : %zu bytes\n",	stat->used_size);
	zy_mm_info("used_pct  : %zu%%\n",		stat->used_pct);

	zy_mm_info("total page count : %zu\n",	stat->pages);
	zy_mm_info("free  page count : %zu\n",	stat->free_page);

	zy_mm_info("small slab use page : %zu,\tbytes : %zu\n",	stat->p_small, stat->b_small);
	zy_mm_info("exact slab use page : %zu,\tbytes : %zu\n",	stat->p_exact, stat->b_exact);
	zy_mm_info("big   slab use page : %zu,\tbytes : %zu\n",	stat->p_big,   stat->b_big);
	zy_mm_info("page  slab use page : %zu,\tbytes : %zu\n",	stat->p_page,  stat->b_page);

	zy_mm_info("max free pages : %zu\n",		stat->max_free_pages);
}

#ifdef PAGE_MERGE
static zy_mm_int_t
zy_mm_slab_empty(zy_mm_slab_pool_t *pool, zy_mm_slab_page_t *page)
{
	zy_mm_slab_page_t *prev;

	if (page->slab == 0) {
		return 1;
	}

	//page->prev == PAGE | SMALL | EXACT | BIG
	if (page->next == NULL ) {
		return 0;
	}

	prev = (zy_mm_slab_page_t *)(page->prev & ~ZY_MM_SLAB_PAGE_MASK);
	while (prev >= pool->pages) {
		prev = (zy_mm_slab_page_t *)(prev->prev & ~ZY_MM_SLAB_PAGE_MASK);
	};

	if (prev == &pool->free) {
		return 1;
	}

	return 0;
}
#endif
