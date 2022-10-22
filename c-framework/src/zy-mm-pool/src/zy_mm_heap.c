#include <string.h>

#include "zy_mm_malloc.h"
#include "list.h"
#include "zy_mm_lock.h"
#include "zy_mm_log.h"

/***************************************************************************/
// made static to avoid conflicts with newlib
/***************************************************************************/

#define MM_DEBUG_STACK          (4)
#define KMALLOC_DEBUG           (0)
#define KMALLOC_HEAD_MAGIC      ((size_t)0x1234abcd1234abcd)
#define KMALLOC_END_MAGIC       ((size_t)0xabcd1234abcd1234)
#define KMALLOC_FREE_MAGIC      ((size_t)0xabcdabcdabcdabcd)

#define top(ar_ptr)             ((ar_ptr)->top)

/* Mapped memory in non-main arenas (reliable only for NO_THREADS). */

/* A heap is a single contiguous memory region holding (coalesceable) malloc_chunks.
 Not used unless compiling with USE_ARENAS. */

/* If THREAD_STATS is non-zero, some statistics on mutex locking are computed. */
// static __thread size_t kmalloc_initial_size, kmalloc_initial_stat = 1;

typedef struct zy_mm_heap_info_s {
  zy_mm_mstate_t             *ar_ptr; /* Arena for this heap. */
  struct zy_mm_heap_info_s   *prev;   /* Previous heap. */
  size_t                      size;    /* Current size in bytes. */
  size_t                      pad;     /* Make sure the following data is properly aligned. */
} zy_mm_heap_info_t;

struct kmalloc_head{
  struct list_head    list;
  void                *start, *obj;
  size_t              total_size, obj_size;
  int                 module;
  int                 age, cpu;
  struct kmem_cache   *slab;
  size_t              magic;
  void                *stack[MM_DEBUG_STACK];
};
struct kmalloc_end {
  size_t  magic;
};

static zy_mm_mstate_t *zy_mm_new_kmalloc(void *addr, size_t size)
{
  zy_mm_mstate_t *a;
  zy_mm_heap_info_t *h;
  char *ptr;
  unsigned long misalign;
  /* Must leave room for struct zy_mm_mstate_t, arena ptrs, etc., totals about 2400 bytes */
  if (!addr || (size < malloc_getpagesize)) {
    return(NULL);
  }
  /* We must zero out the arena as the malloc code assumes this. */
  memset(addr, 0, size);

  h = (zy_mm_heap_info_t *)addr;
  h->size = size;

  a = h->ar_ptr = (zy_mm_mstate_t *)(h+1);
  zy_mm_malloc_init_state(a);
  /*a->next = NULL;*/
  a->system_mem = a->max_system_mem = h->size;
  a->next = a;

  /* Set up the top chunk, with proper alignment. */
  ptr = (char *)(a + 1);
  misalign = (unsigned long)chunk2mem(ptr) & MALLOC_ALIGN_MASK;
  if (misalign > 0) {
    ptr += MALLOC_ALIGNMENT - misalign;
  }
  top(a) = (mchunkptr)ptr;
  set_head(top(a), (((char*)h + h->size) - ptr) | PREV_INUSE);

  return a;
}

static int zy_mm_add_arena(zy_mm_mstate_t **arena_list, void *ptr, size_t size)
{
  zy_mm_mstate_t *a = NULL;
  // zy_mm_dbg("heap, add_arena list[%p],old[%p],new[%p]\n",*arena_list,ptr,a);
  /* Enforce required alignement, and adjust size */
  int misaligned = ((size_t)ptr) & (MALLOC_ALIGNMENT - 1);
  if (misaligned) {
    ptr = (char*)ptr + MALLOC_ALIGNMENT - misaligned;
    size -= MALLOC_ALIGNMENT - misaligned;
  }

  // zy_mm_dbg("heap, Adding arena at addr: %p, size %d\n", ptr, size);
  a = zy_mm_new_kmalloc(ptr, size);  /* checks ptr and size */
  if (!a) {
    return(-1);
  }

  mutex_init(&a->mutex);
  mutex_lock(&a->mutex);

  if (*arena_list) {
    zy_mm_mstate_t *ar_ptr = *arena_list;
    (void)mutex_lock(&ar_ptr->mutex);
    a->next = ar_ptr->next;  // lock held on a and ar_ptr
    ar_ptr->next = a;
    (void)mutex_unlock(&ar_ptr->mutex);
  } else {
      // zy_mm_dbg("heap, arena_list: %p, NULL: %p\n", *arena_list, a);
    *arena_list = a;
    a->next = a;
  }

  // zy_mm_dbg("heap, add_arena - list: %p, list->next: %p\n", *arena_list, ((zy_mm_mstate_t*)*arena_list)->next);

  // unlock, since it is not going to be used immediately
  (void)mutex_unlock(&a->mutex);

  return(0);
}

static zy_mm_mstate_t *mm_init_one(int cpu, void* addr_start, size_t section_size)
{
  zy_mm_mstate_t *arena = NULL;
  if (zy_mm_add_arena(&arena, addr_start, section_size) < 0) {
    zy_mm_error("heap, addr_start[%p] fail to add arena[%p].\n", addr_start, arena);
    return NULL;
  }
  zy_mm_malloc_stat_init(arena, section_size);
  return arena;
}

zy_mm_mstate_t *zy_mm_init_malloc(void* addr_start, size_t size)
{
  zy_mm_mstate_t *pool = mm_init_one(0, addr_start, size);
  zy_mm_dbg("heap, %s, init addr_start[%p] arena size %uM\n",__FUNCTION__,addr_start,(unsigned)(size / (1024 * 1024)));
  // if (!zy_mm_malloc_initialized) {
  //   return pool;
  // } else if(pool==NULL) {
  //   STATISTICS_INC(mem_init_fail);
  // } else {
  //   STATISTICS_INC(mem_init_succ);
  // }
  return pool;
}

// static inline void *__kmalloc_prepare(void* start, void *obj, size_t total_size, size_t obj_size)
// {
// 	struct kmalloc_head *head;
// 	struct kmalloc_end *end;
//  struct kmalloc_stat_t info;

  // if (unlikely(!start)) {
    // HISTORY_INC(kmalloc_fail);
  // } else if (likely(start >= info->start && start < info->start + info->size)) {
    // info->local++;
    // HISTORY_INC(kmalloc_local);
  // }
  // info->total++;

  // if (!KMALLOC_DEBUG) {
  // 	return start;
  // }

  // if (!start) {
  // 	return NULL;
  // }

  // assert(obj >= start + sizeof(*head));
  // assert(total_size >= obj_size + sizeof(*head) + sizeof(*end));
  // head = obj - sizeof(*head);
  // memset(head, 0, sizeof(*head));
  // end = obj + obj_size;
  // head->start = start;
  // head->obj = obj;
  // head->total_size = total_size;
  // head->obj_size = obj_size;
  // head->magic = KMALLOC_HEAD_MAGIC;
  // end->magic = KMALLOC_END_MAGIC;
  // return obj;
// }
