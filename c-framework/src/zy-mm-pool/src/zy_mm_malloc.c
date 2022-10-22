#include <assert.h>
#include <string.h>

#include "zy_mm_malloc.h"
#include "zy_mm_lock.h"
#include "zy_mm_log.h"

/* ---------- description of Internal routines ------------ */
/*
  realloc(void* p, size_t n)
  Returns a pointer to a chunk of size n that contains the same data
  as does chunk p up to the minimum of (n, p's size) bytes, or null
  if no space is available.

  The returned pointer may or may not be the same as p. The algorithm
  prefers extending p when possible, otherwise it employs the
  equivalent of a malloc-copy-free sequence.

  If p is null, realloc is equivalent to malloc.

  If space is not available, realloc returns null, errno is set (if on
  ANSI) and p is NOT freed.

  if n is for fewer bytes than already held by p, the newly unused
  space is lopped off and freed if possible.  Unless the #define
  REALLOC_ZERO_BYTES_FREES is set, realloc with a size argument of
  zero (re)allocates a minimum-sized chunk.

  Large chunks that were internally obtained via mmap will always
  be reallocated using malloc-copy-free sequences unless
  the system supports MREMAP (currently only linux).

  The old unix realloc convention of allowing the last-free'd chunk
  to be used as an argument to realloc is not supported.
*/
void*  zy_mm_mm_realloc(zy_mm_mstate_t *ar_ptr, void*, size_t);

/*
  cfree(void* p);
  Equivalent to free(p).

  cfree is needed/defined on some systems that pair it with calloc,
  for odd historical reasons (such as: cfree is used in example
  code in the first edition of K&R).
*/
void     zy_mm_mm_cfree(void* ar_ptr, void* mem);

/*
  memalign(size_t alignment, size_t n);
  Returns a pointer to a newly allocated chunk of n bytes, aligned
  in accord with the alignment argument.

  The alignment argument should be a power of two. If the argument is
  not a power of two, the nearest greater power is used.
  8-byte alignment is guaranteed by normal malloc calls, so don't
  bother calling memalign with an argument of 8 or less.

  Overreliance on memalign is a sure way to fragment space.
*/
void*  public_mEMALIGn(zy_mm_mstate_t *ar_ptr, size_t, size_t);

/* Internal routines, operating on "arenas".  */
/*  routines.  */
static void*  _int_malloc(zy_mm_mstate_t *, size_t);
static void   _int_free(zy_mm_mstate_t *, void*);
static void*  _int_realloc(zy_mm_mstate_t *, void*, size_t);
static void*  _int_memalign(zy_mm_mstate_t *, size_t, size_t);
static void*  cALLOc(zy_mm_mstate_t *ar_ptr, size_t, size_t) __attribute__((unused));
static size_t mUSABLe(void*) __attribute__((unused));
static struct mallinfo mALLINFo(zy_mm_mstate_t *) __attribute__((unused));

struct malloc_par {
  /* Tunable parameters */
  unsigned long    trim_threshold;
  size_t  top_pad;
  size_t  mmap_threshold;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;

  /* Cache malloc_getpagesize */
  unsigned int     pagesize;

  /* Statistics */
  size_t  mmapped_mem;
  /*size_t  sbrked_mem;*/
  /*size_t  max_sbrked_mem;*/
  size_t  max_mmapped_mem;
  size_t  max_total_mem; /* only kept for NO_THREADS */

  /* First address handed out by MORECORE/sbrk.  */
  char*            sbrk_base;
};

/* There are several instances of this struct ("arenas") in this
   malloc.  If you are adapting this malloc in a way that does NOT use
   a static or mmapped zy_mm_mstate_t, you MUST explicitly zero-fill it
   before using. This malloc relies on the property that zy_mm_mstate_t
   is initialized to all zeroes (as is true of C statics).  */



/*
  Initialize a zy_mm_mstate_t struct.

  This is called only from within malloc_consolidate, which needs
  be called in the same contexts anyway.  It is never called directly
  outside of malloc_consolidate because some optimizing compilers try
  to inline it at all call points, which turns out not to be an
  optimization at all. (Inlining it in malloc_consolidate is fine though.)
*/

void zy_mm_malloc_init_state(zy_mm_mstate_t *av)
{
  int     i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i) {
    bin = bin_at(av,i);
    bin->fd = bin->bk = bin;
  }

  set_noncontiguous(av);

  set_max_fast(av, DEFAULT_MXFAST);

  av->top = initial_top(av);
}

/*
   Other internal utilities operating on mstates
*/
void zy_mm_malloc_consolidate(zy_mm_mstate_t *);

/* ------------------- Support for multiple arenas -------------------- */
/*
 * From the GCC manual:
 *
 * Many functions have no effects except the return value and their
 * return value depends only on the parameters and/or global
 * variables.  Such a function can be subject to common subexpression
 * elimination and loop optimization just as an arithmetic operator
 * would be.
 * [...]
 */
#ifndef __maybe_unused
#define __maybe_unused		__attribute__((unused))
#endif

/*
  Debugging support

  These routines make a number of assertions about the states
  of data structures that should be true at all times. If any
  are not true, it's very likely that a user program has somehow
  trashed memory. (It's also possible that there is a coding error
  in malloc. In which case, please report it!)
*/

#if ! MALLOC_DEBUG

#define check_chunk(A,P)
#define check_free_chunk(A,P)
#define check_inuse_chunk(A,P)
#define check_remalloced_chunk(A,P,N)
#define check_malloced_chunk(A,P,N)
#define check_malloc_state(A)

#else

#define check_chunk(A,P)              do_check_chunk(A,P)
#define check_free_chunk(A,P)         do_check_free_chunk(A,P)
#define check_inuse_chunk(A,P)        do_check_inuse_chunk(A,P)
#define check_remalloced_chunk(A,P,N) do_check_remalloced_chunk(A,P,N)
#define check_malloced_chunk(A,P,N)   do_check_malloced_chunk(A,P,N)
#define check_malloc_state(A)         do_check_malloc_state(A)

/*
  Properties of all chunks
*/
static void do_check_chunk(zy_mm_mstate_t *av, mchunkptr p)
{
  unsigned long sz __maybe_unused = chunksize(p);
  /* min and max possible addresses assuming contiguous allocation */
  char* max_address = (char*)(av->top) + chunksize(av->top);
  char* min_address __maybe_unused = max_address - av->system_mem;

  if (!chunk_is_mmapped(p)) {

    /* Has legal address ... */
    if (p != av->top) {
      if (contiguous(av)) {
        assert(((char*)p) >= min_address);
        assert(((char*)p + sz) <= ((char*)(av->top)));
      }
    } else {
      /* top size is always at least MINSIZE */
      assert((unsigned long)(sz) >= MINSIZE);
      /* top predecessor always marked inuse */
      assert(prev_inuse(p));
    }
  } else {
#if HAVE_MMAP
    /* address is outside main heap  */
    if (contiguous(av) && av->top != initial_top(av)) {
      assert(((char*)p) < min_address || ((char*)p) > max_address);
    }
    /* chunk is page-aligned */
    assert(((p->prev_size + sz) & (mp_.pagesize-1)) == 0);
    /* mem is aligned */
    assert(aligned_OK(chunk2mem(p)));
#else
    /* force an appropriate assert violation if debug set */
    assert(!chunk_is_mmapped(p));
#endif
  }
}

/*
  Properties of free chunks
*/
static void do_check_free_chunk(zy_mm_mstate_t *av, mchunkptr p)
{
  size_t sz = p->size & ~(PREV_INUSE);
  mchunkptr next __maybe_unused = chunk_at_offset(p, sz);

  do_check_chunk(av, p);

  /* Chunk must claim to be free ... */
  assert(!inuse(p));
  assert (!chunk_is_mmapped(p));

  /* Unless a special marker, must have OK fields */
  if ((unsigned long)(sz) >= MINSIZE) {
    assert((sz & MALLOC_ALIGN_MASK) == 0);
    assert(aligned_OK(chunk2mem(p)));
    /* ... matching footer field */
    assert(next->prev_size == sz);
    /* ... and is fully consolidated */
    assert(prev_inuse(p));
    assert (next == av->top || inuse(next));

    /* ... and has minimally sane links */
    assert(p->fd->bk == p);
    assert(p->bk->fd == p);
  } else {
    /* markers are always of size SIZE_SZ */
    assert(sz == SIZE_SZ);
  }
}

/*
  Properties of inuse chunks
*/
static void do_check_inuse_chunk(zy_mm_mstate_t *av, mchunkptr p)
{
  mchunkptr next;

  do_check_chunk(av, p);

  assert(av == arena_for_chunk(p));
  if (chunk_is_mmapped(p))
    return; /* mmapped chunks have no next/prev */

  /* Check whether it claims to be in use ... */
  assert(inuse(p));

  next = next_chunk(p);

  /* ... and is surrounded by OK chunks.
    Since more things can be checked with free chunks than inuse ones,
    if an inuse chunk borders them and debug is on, it's worth doing them.
  */
  if (!prev_inuse(p)) {
    /* Note that we cannot even look at prev unless it is not inuse */
    mchunkptr prv = prev_chunk(p);
    assert(next_chunk(prv) == p);
    do_check_free_chunk(av, prv);
  }

  if (next == av->top) {
    assert(prev_inuse(next));
    assert(chunksize(next) >= MINSIZE);
  } else if (!inuse(next)) {
    do_check_free_chunk(av, next);
  }
}

/*
  Properties of chunks recycled from fastbins
*/
static void do_check_remalloced_chunk(zy_mm_mstate_t *av, mchunkptr p, size_t s)
{
  size_t sz __maybe_unused = p->size & ~(PREV_INUSE);

  if (!chunk_is_mmapped(p)) {
    assert(av == arena_for_chunk(p));
  }

  do_check_inuse_chunk(av, p);

  /* Legal size ... */
  assert((sz & MALLOC_ALIGN_MASK) == 0);
  assert((unsigned long)(sz) >= MINSIZE);
  /* ... and alignment */
  assert(aligned_OK(chunk2mem(p)));
  /* chunk is less than MINSIZE more than request */
  assert((long)(sz) - (long)(s) >= 0);
  assert((long)(sz) - (long)(s + MINSIZE) < 0);
}

/*
  Properties of nonrecycled chunks at the point they are malloced
*/
static void do_check_malloced_chunk(zy_mm_mstate_t *av, mchunkptr p, size_t s)
{
  /* same as recycled case ... */
  do_check_remalloced_chunk(av, p, s);

  /*
    ... plus,  must obey implementation invariant that prev_inuse is
    always true of any allocated chunk; i.e., that each allocated
    chunk borders either a previously allocated and still in-use
    chunk, or the base of its memory arena. This is ensured
    by making all allocations from the the `lowest' part of any found
    chunk.  This does not necessarily hold however for chunks
    recycled via fastbins.
  */

  assert(prev_inuse(p));
}


/*
  Properties of zy_mm_mstate_t.

  This may be useful for debugging malloc, as well as detecting user
  programmer errors that somehow write into zy_mm_mstate_t.

  If you are extending or experimenting with this malloc, you can
  probably figure out how to hack this routine to print out or
  display chunk addresses, sizes, bins, and other instrumentation.
*/

static void do_check_malloc_state(zy_mm_mstate_t *av)
{
  int i;
  mchunkptr p;
  mchunkptr q;
  mbinptr b;
  unsigned int binbit;
  int empty;
  unsigned int idx __maybe_unused;
  size_t size;
  unsigned long total = 0;
  int max_fast_bin;

  /* internal size_t must be no wider than pointer type */
  assert(sizeof(size_t) <= sizeof(char*));

  /* alignment is a power of 2 */
  assert((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-1)) == 0);

  /* cannot run remaining checks until fully initialized */
  if (av->top == 0 || av->top == initial_top(av))
    return;


  /* properties of fastbins */

  /* max_fast is in allowed range */
  assert((av->max_fast & ~1) <= request2size(MAX_FAST_SIZE));

  max_fast_bin = fastbin_index(av->max_fast);

  for (i = 0; i < NFASTBINS; ++i) {
    p = av->fastbins[i];

    /* all bins past max_fast are empty */
    if (i > max_fast_bin)
      assert(p == 0);

    while (p != 0) {
      /* each chunk claims to be inuse */
      do_check_inuse_chunk(av, p);
      total += chunksize(p);
      /* chunk belongs in this bin */
      assert(fastbin_index(chunksize(p)) == i);
      p = p->fd;
    }
  }

  if (total != 0)
    assert(have_fastchunks(av));
  else if (!have_fastchunks(av))
    assert(total == 0);

  /* check normal bins */
  for (i = 1; i < NBINS; ++i) {
    b = bin_at(av,i);

    /* binmap is accurate (except for bin 1 == unsorted_chunks) */
    if (i >= 2) {
      binbit = get_binmap(av,i);
      empty = last(b) == b;
      if (!binbit)
        assert(empty);
      else if (!empty)
        assert(binbit);
    }

    for (p = last(b); p != b; p = p->bk) {
      /* each chunk claims to be free */
      do_check_free_chunk(av, p);
      size = chunksize(p);
      total += size;
      if (i >= 2) {
        /* chunk belongs in bin */
        idx = bin_index(size);
        assert(idx == (unsigned int)i);
        /* lists are sorted */
        if ((unsigned long) size >= (unsigned long)(FIRST_SORTED_BIN_SIZE)) {
            assert(p->bk == b ||
            (unsigned long)chunksize(p->bk) >=
            (unsigned long)chunksize(p));
        }
      }
      /* chunk is followed by a legal chain of inuse chunks */
      for (q = next_chunk(p);
           (q != av->top && inuse(q) &&
             (unsigned long)(chunksize(q)) >= MINSIZE);
           q = next_chunk(q))
        do_check_inuse_chunk(av, q);
    }
  }

  /* top chunk is OK */
  check_chunk(av, av->top);

  /* sanity checks for statistics */


  assert((unsigned long)(av->system_mem) <=
         (unsigned long)(av->max_system_mem));


}
#endif



/* ----------- Routines dealing with system allocation -------------- */

/* No system allocation routines supported */


/*------------------------ Public wrappers. --------------------------------*/

#undef DEBUG_MALLOC
void *zy_mm_malloc(void* ar_ptr, size_t bytes)
{
  zy_mm_mstate_t *orig_ar_ptr;
  zy_mm_mstate_t *in_ar_ptr = (zy_mm_mstate_t *) ar_ptr;
  void *victim = NULL;
  static zy_mm_mstate_t *debug_prev_ar;  // debug only!
#ifdef DEBUG_MALLOC
  int arena_cnt=0;
#endif
  // if (zy_mm_malloc_initialized) {
  //   STATISTICS_INC(mem_malloc);
  // }

  if (!in_ar_ptr) {
    return(NULL);
  }

  if (debug_prev_ar != in_ar_ptr) {
    // zy_mm_dbg("malloc, New malloc[%p]: bytes[%lu]\n", in_ar_ptr, bytes);
#ifdef DEBUG_MALLOC
    // zy_mm_dbg("malloc, lock wait count for arena: %p is %ld\n", in_ar_ptr, in_ar_ptr->mutex.locked);
#endif
    debug_prev_ar = in_ar_ptr;
  }
  orig_ar_ptr = in_ar_ptr;

  // try to get an arena without contention
  do {
#ifdef DEBUG_MALLOC
    arena_cnt++;
#endif
    if (!mutex_trylock(&in_ar_ptr->mutex)) {
      // we locked it
      victim = _int_malloc(in_ar_ptr, bytes);
      (void)mutex_unlock(&in_ar_ptr->mutex);
      if(victim) {
        break;
      }
    }
    in_ar_ptr = in_ar_ptr->next;
  } while (in_ar_ptr != orig_ar_ptr);

  // we couldn't get the memory without contention, so try all
  // arenas.  SLOW!
  if (!victim) {
    in_ar_ptr = orig_ar_ptr;
    do {
#ifdef DEBUG_MALLOC
      arena_cnt++;
#endif
      mutex_lock(&in_ar_ptr->mutex);
      victim = _int_malloc(in_ar_ptr, bytes);
      (void)mutex_unlock(&in_ar_ptr->mutex);
      if(victim) {
        break;
      }
      in_ar_ptr = in_ar_ptr->next;
    } while (in_ar_ptr != orig_ar_ptr);
  }

  assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
  in_ar_ptr == arena_for_chunk(mem2chunk(victim)));

  if (!victim) {
    zy_mm_error("malloc, ptr[%p] malloc bytes[%lu] mem failed,used[%lu],total[%lu].\n",
      in_ar_ptr, bytes, in_ar_ptr->stat.used, in_ar_ptr->stat.total);
#ifdef DEBUG_MALLOC
    abort();
#endif
  }

  // zy_mm_dbg("malloc, Malloc(%lu) = %p\n", bytes, victim);
  return victim;
}

#undef DEBUG_MALLOC
void zy_mm_kfree(void* ar_ptr,void* mem)
{
  // zy_mm_dbg("malloc, zy_mm public free(%p)\n", mem);
  if(ar_ptr==NULL || mem==NULL) {
    // if (zy_mm_malloc_initialized) {
    //   STATISTICS_INC(mem_null);
    // }
    /* NOTE: when hs alloc failed, free with nil */
    return;
  }
  zy_mm_mstate_t *in_ar_ptr = (zy_mm_mstate_t *) ar_ptr;

#if THREAD_STATS
  if(mutex_trylock(&in_ar_ptr->mutex))
    ++(in_ar_ptr->stat_lock_direct);
  else {
    (void)mutex_lock(&in_ar_ptr->mutex);
    ++(in_ar_ptr->stat_lock_wait);
  }
#else
  (void)mutex_lock(&in_ar_ptr->mutex);
#endif
  _int_free(in_ar_ptr, mem);
  (void)mutex_unlock(&in_ar_ptr->mutex);
}

void*
zy_mm_mm_realloc(zy_mm_mstate_t *ar_ptr, void* oldmem, size_t bytes)
{
  size_t    nb __maybe_unused;      /* padded request size */

  mchunkptr oldp;             /* chunk corresponding to oldmem */
  size_t    oldsize __maybe_unused; /* its size */

  void* newp;             /* chunk to return */


#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL) {
    zy_mm_kfree(ar_ptr, oldmem);
    return 0;
  }
#endif

  /* realloc of null is supposed to be same as malloc */
  if (oldmem == 0) return zy_mm_malloc(ar_ptr, bytes);

  oldp    = mem2chunk(oldmem);
  oldsize = chunksize(oldp);

  checked_request2size(bytes, nb);


  ar_ptr = arena_for_chunk(oldp);
  (void)mutex_lock(&ar_ptr->mutex);


  newp = _int_realloc(ar_ptr, oldmem, bytes);

  (void)mutex_unlock(&ar_ptr->mutex);
  assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
	 ar_ptr == arena_for_chunk(mem2chunk(newp)));
  return newp;
}

#undef DEBUG_MEMALIGN
void*
public_mEMALIGn(zy_mm_mstate_t *ar_ptr, size_t alignment, size_t bytes)
{
  zy_mm_mstate_t *orig_ar_ptr;
  void *p = NULL;
#ifdef DEBUG_MEMALIGN
  int arena_cnt=0;
#endif


  /* If need less alignment than we give anyway, just relay to malloc */
  if (alignment <= MALLOC_ALIGNMENT) return zy_mm_malloc(ar_ptr, bytes);

  /* Otherwise, ensure that it is at least a minimum chunk size */
  if (alignment <  MINSIZE) alignment = MINSIZE;

  if (!ar_ptr) {
    return(NULL);
  }

  orig_ar_ptr = ar_ptr;


  // try to get an arena without contention
  do {
#ifdef DEBUG_MEMALIGN
   arena_cnt++;
#endif
    if (mutex_trylock(&ar_ptr->mutex)) {
      // we locked it
      p = _int_memalign(ar_ptr, alignment, bytes);
      (void)mutex_unlock(&ar_ptr->mutex);
      if (p) {
        break;
      }
    }
    ar_ptr = ar_ptr->next;
  } while (ar_ptr != orig_ar_ptr);

  // we couldn't get the memory without contention, so try all
  // arenas.  SLOW!
  if (!p) {
#ifdef DEBUG_MEMALIGN
   arena_cnt++;
#endif
    ar_ptr = orig_ar_ptr;
    do {
      mutex_lock(&ar_ptr->mutex);
      p = _int_memalign(ar_ptr, alignment, bytes);
      (void)mutex_unlock(&ar_ptr->mutex);
      if(p) {
        break;
      }
      ar_ptr = ar_ptr->next;
    } while (ar_ptr != orig_ar_ptr);
  }

  if (p) {
    assert(ar_ptr == arena_for_chunk(mem2chunk(p)));
  } else {
    zy_mm_dbg("malloc, Memalign failed: align: 0x%lx, size: %ld.\n", alignment, bytes);
  }

  assert(!p || ar_ptr == arena_for_chunk(mem2chunk(p)));
  return p;
}

void* zy_mm_mm_cmalloc(void* ar_ptr, size_t n, size_t elem_size)
{
  size_t sz;
  void* mem;

  /* FIXME: check for overflow on multiplication.  */
  sz = n * elem_size;

  mem = zy_mm_malloc(ar_ptr, sz);
  if (mem) {
    memset(mem, 0, sz);
  }

  return mem;
}

void zy_mm_mm_cfree(void* ar_ptr,void* m)
{
  zy_mm_kfree(ar_ptr,m);
}

/*
  ------------------------------ malloc ------------------------------
*/

static void*
__int_malloc(zy_mm_mstate_t *av, size_t bytes)
{
  size_t nb;               /* normalized request size */
  unsigned int    idx;              /* associated bin index */
  mbinptr         bin;              /* associated bin */
  mfastbinptr*    fb;               /* associated fastbin */

  mchunkptr       victim;           /* inspected/selected chunk */
  size_t size;             /* its size */
  int             victim_index;     /* its bin index */

  mchunkptr       remainder;        /* remainder from a split */
  unsigned long   remainder_size;   /* its size */

  unsigned int    block;            /* bit map traverser */
  unsigned int    bit;              /* bit map traverser */
  unsigned int    map;              /* current word of binmap */

  mchunkptr       fwd;              /* misc temp for linking */
  mchunkptr       bck;              /* misc temp for linking */

  /*
    Convert request size to internal form by adding SIZE_SZ bytes
    overhead plus possibly more to obtain necessary alignment and/or
    to obtain a size of at least MINSIZE, the smallest allocatable
    size. Also, checked_request2size traps (returning 0) request sizes
    that are so large that they wrap around zero when padded and
    aligned.
  */


  checked_request2size(bytes, nb);

  /*
    If the size qualifies as a fastbin, first check corresponding bin.
    This code is safe to execute even if av is not yet initialized, so we
    can try it without checking, which saves some time on this fast path.
  */

  if ((unsigned long)(nb) <= (unsigned long)(av->max_fast)) {
    fb = &(av->fastbins[(fastbin_index(nb))]);
    if ( (victim = *fb) != 0) {
      *fb = victim->fd;
      check_remalloced_chunk(av, victim, nb);
      set_arena_for_chunk(victim, av);
      return chunk2mem(victim);
    }
  }

  /*
    If a small request, check regular bin.  Since these "smallbins"
    hold one size each, no searching within bins is necessary.
    (For a large request, we need to wait until unsorted chunks are
    processed to find best fit. But for small ones, fits are exact
    anyway, so we can check now, which is faster.)
  */

  if (in_smallbin_range(nb)) {
    idx = smallbin_index(nb);
    bin = bin_at(av,idx);

    if ( (victim = last(bin)) != bin) {
      if (victim == 0) /* initialization check */
        zy_mm_malloc_consolidate(av);
      else {
        bck = victim->bk;
        set_inuse_bit_at_offset(victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        set_arena_for_chunk(victim, av);
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }
    }
  } else {
  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
  */
    idx = largebin_index(nb);
    if (have_fastchunks(av))
      zy_mm_malloc_consolidate(av);
  }

  /*
    Process recently freed or remaindered chunks, taking one only if
    it is exact fit, or, if this a small request, the chunk is remainder from
    the most recent non-exact fit.  Place other traversed chunks in
    bins.  Note that this step is the only place in any routine where
    chunks are placed in bins.

    The outer loop here is needed because we might not realize until
    near the end of malloc that we should have consolidated, so must
    do so and retry. This happens at most once, and only when we would
    otherwise need to expand memory to service a "small" request.
  */

  for(;;) {

    while ( (victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
      bck = victim->bk;
      size = chunksize(victim);

      /*
         If a small request, try to use last remainder if it is the
         only chunk in unsorted bin.  This helps promote locality for
         runs of consecutive small requests. This is the only
         exception to best-fit, and applies only when there is
         no exact fit for a small chunk.
      */

      if (in_smallbin_range(nb) &&
          bck == unsorted_chunks(av) &&
          victim == av->last_remainder &&
          (unsigned long)(size) > (unsigned long)(nb + MINSIZE)) {

        /* split and reattach remainder */
        remainder_size = size - nb;
        remainder = chunk_at_offset(victim, nb);
        unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
        av->last_remainder = remainder;
        remainder->bk = remainder->fd = unsorted_chunks(av);

        set_head(victim, nb | PREV_INUSE);
        set_head(remainder, remainder_size | PREV_INUSE);
        set_foot(remainder, remainder_size);

        set_arena_for_chunk(victim, av);
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }

      /* remove from unsorted list */
      unsorted_chunks(av)->bk = bck;
      bck->fd = unsorted_chunks(av);

      /* Take now instead of binning if exact fit */

      if (size == nb) {
        set_inuse_bit_at_offset(victim, size);
        set_arena_for_chunk(victim, av);
        check_malloced_chunk(av, victim, nb);
        return chunk2mem(victim);
      }

      /* place chunk in bin */

      if (in_smallbin_range(size)) {
        victim_index = smallbin_index(size);
        bck = bin_at(av, victim_index);
        fwd = bck->fd;
      } else {
        victim_index = largebin_index(size);
        bck = bin_at(av, victim_index);
        fwd = bck->fd;

        if (fwd != bck) {
          /* if smaller than smallest, place first */
          if ((unsigned long)(size) < (unsigned long)(bck->bk->size)) {
            fwd = bck;
            bck = bck->bk;
          } else if ((unsigned long)(size) >= (unsigned long)(FIRST_SORTED_BIN_SIZE)) {
            /* maintain large bins in sorted order */
            size |= PREV_INUSE; /* Or with inuse bit to speed comparisons */
            while ((unsigned long)(size) < (unsigned long)(fwd->size)) {
              fwd = fwd->fd;
            }
            bck = fwd->bk;
          }
        }
      }

      mark_bin(av, victim_index);
      victim->bk = bck;
      victim->fd = fwd;
      fwd->bk = victim;
      bck->fd = victim;
    }

    /*
      If a large request, scan through the chunks of current bin in
      sorted order to find smallest that fits.  This is the only step
      where an unbounded number of chunks might be scanned without doing
      anything useful with them. However the lists tend to be short.
    */

    if (!in_smallbin_range(nb)) {
      bin = bin_at(av, idx);

      for (victim = last(bin); victim != bin; victim = victim->bk) {
        size = chunksize(victim);
        if ((unsigned long)(size) >= (unsigned long)(nb)) {
          remainder_size = size - nb;
          _malloc_unlink(victim, bck, fwd);

          /* Exhaust */
          if (remainder_size < MINSIZE) {
            set_inuse_bit_at_offset(victim, size);
              set_arena_for_chunk(victim, av);
            check_malloced_chunk(av, victim, nb);
            return chunk2mem(victim);
          } else {
            /* Split */
            remainder = chunk_at_offset(victim, nb);
            unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
            remainder->bk = remainder->fd = unsorted_chunks(av);
            set_head(victim, nb | PREV_INUSE);
            set_head(remainder, remainder_size | PREV_INUSE);
            set_foot(remainder, remainder_size);
              set_arena_for_chunk(victim, av);
            check_malloced_chunk(av, victim, nb);
            return chunk2mem(victim);
          }
        }
      }
    }

    /*
      Search for a chunk by scanning bins, starting with next largest
      bin. This search is strictly by best-fit; i.e., the smallest
      (with ties going to approximately the least recently used) chunk
      that fits is selected.

      The bitmap avoids needing to check that most blocks are nonempty.
      The particular case of skipping all bins during warm-up phases
      when no chunks have been returned yet is faster than it might look.
    */

    ++idx;
    bin = bin_at(av,idx);
    block = idx2block(idx);
    map = av->binmap[block];
    bit = idx2bit(idx);

    for (;;) {

      /* Skip rest of block if there are no more set bits in this block.  */
      if (bit > map || bit == 0) {
        do {
          if (++block >= BINMAPSIZE)  /* out of bins */
            goto use_top;
        } while ( (map = av->binmap[block]) == 0);

        bin = bin_at(av, (block << BINMAPSHIFT));
        bit = 1;
      }

      /* Advance to bin with set bit. There must be one. */
      while ((bit & map) == 0) {
        bin = next_bin(bin);
        bit <<= 1;
        assert(bit != 0);
      }

      /* Inspect the bin. It is likely to be non-empty */
      victim = last(bin);

      /*  If a false alarm (empty bin), clear the bit. */
      if (victim == bin) {
        av->binmap[block] = map &= ~bit; /* Write through */
        bin = next_bin(bin);
        bit <<= 1;
      } else {
        size = chunksize(victim);

        /*  We know the first chunk in this bin is big enough to use. */
        assert((unsigned long)(size) >= (unsigned long)(nb));

        remainder_size = size - nb;

        /* _malloc_unlink */
        bck = victim->bk;
        bin->bk = bck;
        bck->fd = bin;

        /* Exhaust */
        if (remainder_size < MINSIZE) {
          set_inuse_bit_at_offset(victim, size);
          set_arena_for_chunk(victim, av);
          check_malloced_chunk(av, victim, nb);
          return chunk2mem(victim);
        } else {
        /* Split */
          remainder = chunk_at_offset(victim, nb);

          unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
          remainder->bk = remainder->fd = unsorted_chunks(av);
          /* advertise as last remainder */
          if (in_smallbin_range(nb))
            av->last_remainder = remainder;

          set_head(victim, nb | PREV_INUSE);
          set_head(remainder, remainder_size | PREV_INUSE);
          set_foot(remainder, remainder_size);
          set_arena_for_chunk(victim, av);
          check_malloced_chunk(av, victim, nb);
          return chunk2mem(victim);
        }
      }
    }

  use_top:
    /*
      If large enough, split off the chunk bordering the end of memory
      (held in av->top). Note that this is in accord with the best-fit
      search rule.  In effect, av->top is treated as larger (and thus
      less well fitting) than any other available chunk since it can
      be extended to be as large as necessary (up to system
      limitations).

      We require that av->top always exists (i.e., has size >=
      MINSIZE) after initialization, so if it would otherwise be
      exhuasted by current request, it is replenished. (The main
      reason for ensuring it exists is that we may need MINSIZE space
      to put in fenceposts in sysmalloc.)
    */

    victim = av->top;
    size = chunksize(victim);

    if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
      remainder_size = size - nb;
      remainder = chunk_at_offset(victim, nb);
      av->top = remainder;
      set_head(victim, nb | PREV_INUSE);
      set_head(remainder, remainder_size | PREV_INUSE);

      set_arena_for_chunk(victim, av);
      check_malloced_chunk(av, victim, nb);
      return chunk2mem(victim);
    } else if (have_fastchunks(av)) {
    /*
      If there is space available in fastbins, consolidate and retry,
      to possibly avoid expanding memory. This can occur only if nb is
      in smallbin range so we didn't consolidate upon entry.
    */
      assert(in_smallbin_range(nb));
      zy_mm_malloc_consolidate(av);
      idx = smallbin_index(nb); /* restore original bin index */
    }
    /*
       Otherwise, relay to handle system-dependent cases
    */
    else
      return(NULL); // sysmalloc not supported
  }
}

void zy_mm_malloc_stat_init(zy_mm_mstate_t *arena, size_t size)
{
  memset(&arena->stat, 0, sizeof(kmalloc_stat_t));
  arena->stat.start = arena;
  arena->stat.total = size;
}

static void kmalloc_stat_malloc(kmalloc_stat_t* stat, size_t size)
{
  stat->used += size;
}
static void kmalloc_stat_free(kmalloc_stat_t* stat, size_t size)
{
  if(stat->used > size)
  stat->used -= size;
}

static void*
_int_malloc(zy_mm_mstate_t *av, size_t bytes)
{
	mchunkptr	chunk;	     /* chunk corresponding to mem */
	size_t size;	         /* its size */
	void *p = __int_malloc(av, bytes);

	if (!p)
		return NULL;

	chunk = mem2chunk(p);
	size = chunksize(chunk);

	kmalloc_stat_malloc(&av->stat, size);
	return p;
}

/*
  ------------------------------ free ------------------------------
*/

static void
_int_free(zy_mm_mstate_t *av, void* mem)
{
  mchunkptr       p;           /* chunk corresponding to mem */
  size_t size;        /* its size */
  mfastbinptr*    fb;          /* associated fastbin */
  mchunkptr       nextchunk;   /* next contiguous chunk */
  size_t nextsize;    /* its size */
  int             nextinuse;   /* true if nextchunk is used */
  size_t prevsize;    /* size of previous contiguous chunk */
  mchunkptr       bck;         /* misc temp for linking */
  mchunkptr       fwd;         /* misc temp for linking */


  /* free(0) has no effect */
  if (mem != 0) {
    p = mem2chunk(mem);
    size = chunksize(p);
    kmalloc_stat_free(&av->stat, size);
    check_inuse_chunk(av, p);

    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    if ((unsigned long)(size) <= (unsigned long)(av->max_fast)

#if TRIM_FASTBINS
        /*
           If TRIM_FASTBINS set, don't place chunks
           bordering top into fastbins
        */
        && (chunk_at_offset(p, size) != av->top)
#endif
        ) {

      set_fastchunks(av);
      fb = &(av->fastbins[fastbin_index(size)]);
      p->fd = *fb;
      *fb = p;
    }

    /*
       Consolidate other non-mmapped chunks as they arrive.
    */

    else if (!chunk_is_mmapped(p)) {
      nextchunk = chunk_at_offset(p, size);
      nextsize = chunksize(nextchunk);
      assert(nextsize > 0);

      /* consolidate backward */
      if (!prev_inuse(p)) {
        prevsize = p->prev_size;
        size += prevsize;
        p = chunk_at_offset(p, -((long) prevsize));
        _malloc_unlink(p, bck, fwd);
      }

      if (nextchunk != av->top) {
        /* get and clear inuse bit */
        nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

        /* consolidate forward */
        if (!nextinuse) {
          _malloc_unlink(nextchunk, bck, fwd);
          size += nextsize;
        } else
	  clear_inuse_bit_at_offset(nextchunk, 0);

        /*
          Place the chunk in unsorted chunk list. Chunks are
          not placed into regular bins until after they have
          been given one chance to be used in malloc.
        */

        bck = unsorted_chunks(av);
        fwd = bck->fd;
        p->bk = bck;
        p->fd = fwd;
        bck->fd = p;
        fwd->bk = p;

        set_head(p, size | PREV_INUSE);
        set_foot(p, size);

        check_free_chunk(av, p);
      }

      /*
         If the chunk borders the current high end of memory,
         consolidate into top
      */

      else {
        size += nextsize;
        set_head(p, size | PREV_INUSE);
        av->top = p;
        check_chunk(av, p);
      }

      /*
        If freeing a large space, consolidate possibly-surrounding
        chunks. Then, if the total unused topmost memory exceeds trim
        threshold, ask malloc_trim to reduce top.

        Unless max_fast is 0, we don't know if there are fastbins
        bordering top, so we cannot tell for sure whether threshold
        has been reached unless fastbins are consolidated.  But we
        don't want to consolidate on each free.  As a compromise,
        consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
        is reached.
      */

      if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
        if (have_fastchunks(av))
          zy_mm_malloc_consolidate(av);
      }
    }
  }
}

/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.

  Also, because this routine needs to be called the first time through
  malloc anyway, it turns out to be the perfect place to trigger
  initialization code.
*/

void zy_mm_malloc_consolidate(zy_mm_mstate_t *av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  size_t size;
  size_t nextsize;
  size_t prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  /*
    If max_fast is 0, we know that av hasn't
    yet been initialized, in which case do so below
  */

  if (av->max_fast != 0) {
    clear_fastchunks(av);

    unsorted_bin = unsorted_chunks(av);

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
    */

    maxfb = &(av->fastbins[fastbin_index(av->max_fast)]);
    fb = &(av->fastbins[0]);
    do {
      if ( (p = *fb) != 0) {
        *fb = 0;

        do {
          check_inuse_chunk(av, p);
          nextp = p->fd;

          /* Slightly streamlined version of consolidation code in free() */
          size = p->size & ~(PREV_INUSE);
          nextchunk = chunk_at_offset(p, size);
          nextsize = chunksize(nextchunk);

          if (!prev_inuse(p)) {
            prevsize = p->prev_size;
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            _malloc_unlink(p, bck, fwd);
          }

          if (nextchunk != av->top) {
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

            if (!nextinuse) {
              size += nextsize;
              _malloc_unlink(nextchunk, bck, fwd);
            } else {
              clear_inuse_bit_at_offset(nextchunk, 0);
            }
            first_unsorted = unsorted_bin->fd;
            unsorted_bin->fd = p;
            first_unsorted->bk = p;

            set_head(p, size | PREV_INUSE);
            p->bk = unsorted_bin;
            p->fd = first_unsorted;
            set_foot(p, size);
          } else {
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
          }
        } while ( (p = nextp) != 0);

      }
    } while (fb++ != maxfb);
  } else {
    zy_mm_malloc_init_state(av);
    check_malloc_state(av);
  }
}

/*
  ------------------------------ realloc ------------------------------
*/

static void*
_int_realloc(zy_mm_mstate_t *av, void* oldmem, size_t bytes)
{
  size_t  nb;              /* padded request size */

  mchunkptr        oldp;            /* chunk corresponding to oldmem */
  size_t  oldsize;         /* its size */

  mchunkptr        newp;            /* chunk to return */
  size_t  newsize;         /* its size */
  void*          newmem;          /* corresponding user mem */

  mchunkptr        next;            /* next contiguous chunk after oldp */

  mchunkptr        remainder;       /* extra space at end of newp */
  unsigned long    remainder_size;  /* its size */

  mchunkptr        bck;             /* misc temp for linking */
  mchunkptr        fwd;             /* misc temp for linking */

  unsigned long    copysize;        /* bytes to copy */
  unsigned int     ncopies;         /* size_t words to copy */
  size_t* s;               /* copy source */
  size_t* d;               /* copy destination */


#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0) {
    _int_free(av, oldmem);
    return 0;
  }
#endif

  /* realloc of null is supposed to be same as malloc */
  if (oldmem == 0) return _int_malloc(av, bytes);

  checked_request2size(bytes, nb);

  oldp    = mem2chunk(oldmem);
  oldsize = chunksize(oldp);

  check_inuse_chunk(av, oldp);

  // force to act like not mmapped
  if (1) {

    if ((unsigned long)(oldsize) >= (unsigned long)(nb)) {
      /* already big enough; split below */
      newp = oldp;
      newsize = oldsize;
    }

    else {
      next = chunk_at_offset(oldp, oldsize);

      /* Try to expand forward into top */
      if (next == av->top &&
          (unsigned long)(newsize = oldsize + chunksize(next)) >=
          (unsigned long)(nb + MINSIZE)) {
        set_head_size(oldp, nb );
        av->top = chunk_at_offset(oldp, nb);
        set_head(av->top, (newsize - nb) | PREV_INUSE);
    	check_inuse_chunk(av, oldp);
        set_arena_for_chunk(oldp, av);
        return chunk2mem(oldp);
      }

      /* Try to expand forward into next chunk;  split off remainder below */
      else if (next != av->top &&
               !inuse(next) &&
               (unsigned long)(newsize = oldsize + chunksize(next)) >=
               (unsigned long)(nb)) {
        newp = oldp;
        _malloc_unlink(next, bck, fwd);
      }

      /* allocate, copy, free */
      else {
        newmem = _int_malloc(av, nb - MALLOC_ALIGN_MASK);
        if (newmem == 0)
          return 0; /* propagate failure */

        newp = mem2chunk(newmem);
        newsize = chunksize(newp);

        /*
          Avoid copy if newp is next chunk after oldp.
        */
        if (newp == next) {
          newsize += oldsize;
          newp = oldp;
        }
        else {
          /*
            Unroll copy of <= 36 bytes (72 if 8byte sizes)
            We know that contents have an odd number of
            size_t-sized words; minimally 3.
          */

          copysize = oldsize - SIZE_SZ;
          s = (size_t*)(oldmem);
          d = (size_t*)(newmem);
          ncopies = copysize / sizeof(size_t);
          assert(ncopies >= 3);

          if (ncopies > 9)
            MALLOC_COPY(d, s, copysize);

          else {
            *(d+0) = *(s+0);
            *(d+1) = *(s+1);
            *(d+2) = *(s+2);
            if (ncopies > 4) {
              *(d+3) = *(s+3);
              *(d+4) = *(s+4);
              if (ncopies > 6) {
                *(d+5) = *(s+5);
                *(d+6) = *(s+6);
                if (ncopies > 8) {
                  *(d+7) = *(s+7);
                  *(d+8) = *(s+8);
                }
              }
            }
          }

          _int_free(av, oldmem);
          set_arena_for_chunk(newp, av);
          check_inuse_chunk(av, newp);
          return chunk2mem(newp);
        }
      }
    }

    /* If possible, free extra space in old or extended chunk */

    assert((unsigned long)(newsize) >= (unsigned long)(nb));

    remainder_size = newsize - nb;

    if (remainder_size < MINSIZE) { /* not enough extra to split off */
      set_head_size(newp, newsize);
      set_inuse_bit_at_offset(newp, newsize);
    }
    else { /* split remainder */
      remainder = chunk_at_offset(newp, nb);
      set_head_size(newp, nb );
      set_head(remainder, remainder_size | PREV_INUSE );
      /* Mark remainder as inuse so free() won't complain */
      set_inuse_bit_at_offset(remainder, remainder_size);
      set_arena_for_chunk(remainder, av);
      _int_free(av, chunk2mem(remainder));
    }

    set_arena_for_chunk(newp, av);
    check_inuse_chunk(av, newp);
    return chunk2mem(newp);
  }

  /*
    Handle mmap cases
  */

  else {
    /* If !HAVE_MMAP, but chunk_is_mmapped, user must have overwritten mem */
    check_malloc_state(av);
    MALLOC_FAILURE_ACTION;
    return 0;
  }
}

/*
  ------------------------------ memalign ------------------------------
*/

static void*
_int_memalign(zy_mm_mstate_t *av, size_t alignment, size_t bytes)
{
  size_t nb;             /* padded  request size */
  char*           m;              /* memory returned by malloc call */
  mchunkptr       p;              /* corresponding chunk */
  char*           brk;            /* alignment point within p */
  mchunkptr       newp;           /* chunk to return */
  size_t newsize;        /* its size */
  size_t leadsize;       /* leading space before alignment point */
  mchunkptr       remainder;      /* spare room at end to split off */
  unsigned long   remainder_size; /* its size */
  size_t size;

  /* If need less alignment than we give anyway, just relay to malloc */

  if (alignment <= MALLOC_ALIGNMENT) return _int_malloc(av, bytes);

  /* Otherwise, ensure that it is at least a minimum chunk size */

  if (alignment <  MINSIZE) alignment = MINSIZE;

  /* Make sure alignment is power of 2 (in case MINSIZE is not).  */
  if ((alignment & (alignment - 1)) != 0) {
    size_t a = MALLOC_ALIGNMENT * 2;
    while ((unsigned long)a < (unsigned long)alignment) a <<= 1;
    alignment = a;
  }

  checked_request2size(bytes, nb);

  /*
    Strategy: find a spot within that chunk that meets the alignment
    request, and then possibly free the leading and trailing space.
  */


  /* Call malloc with worst case padding to hit alignment. */

  m  = (char*)(_int_malloc(av, nb + alignment + MINSIZE));

  if (m == 0) return 0; /* propagate failure */

  p = mem2chunk(m);

  if ((((unsigned long)(m)) % alignment) != 0) { /* misaligned */

    /*
      Find an aligned spot inside chunk.  Since we need to give back
      leading space in a chunk of at least MINSIZE, if the first
      calculation places us at a spot with less than MINSIZE leader,
      we can move to the next aligned spot -- we've allocated enough
      total room so that this is always possible.
    */

    brk = (char*)mem2chunk(((unsigned long)(m + alignment - 1)) &
                           -((signed long) alignment));
    if ((unsigned long)(brk - (char*)(p)) < MINSIZE)
      brk += alignment;

    newp = (mchunkptr)brk;
    leadsize = brk - (char*)(p);
    newsize = chunksize(p) - leadsize;

    /* For mmapped chunks, just adjust offset */
    if (chunk_is_mmapped(p)) {
      newp->prev_size = p->prev_size + leadsize;
      set_head(newp, newsize|IS_MMAPPED);
      set_arena_for_chunk(newp, av);
      return chunk2mem(newp);
    }

    /* Otherwise, give back leader, use the rest */
    set_head(newp, newsize | PREV_INUSE );
    set_inuse_bit_at_offset(newp, newsize);
    set_head_size(p, leadsize);
    set_arena_for_chunk(p, av);
    _int_free(av, chunk2mem(p));
    p = newp;

    assert (newsize >= nb &&
            (((unsigned long)(chunk2mem(p))) % alignment) == 0);
  }

  /* Also give back spare room at the end */
  if (!chunk_is_mmapped(p)) {
    size = chunksize(p);
    if ((unsigned long)(size) > (unsigned long)(nb + MINSIZE)) {
      remainder_size = size - nb;
      remainder = chunk_at_offset(p, nb);
      set_head(remainder, remainder_size | PREV_INUSE );
      set_head_size(p, nb);
      set_arena_for_chunk(remainder, av);
      _int_free(av, chunk2mem(remainder));
    }
  }

  set_arena_for_chunk(p, av);
  check_inuse_chunk(av, p);
  return chunk2mem(p);
}

/*
  ------------------------------ calloc ------------------------------
*/
void* cALLOc(zy_mm_mstate_t *ar_ptr, size_t n_elements, size_t elem_size)
{
  mchunkptr p;
  unsigned long clearsize;
  unsigned long nclears;
  size_t* d;

  void* mem = zy_mm_malloc(ar_ptr, n_elements * elem_size);

  if (mem != 0) {
    p = mem2chunk(mem);

    {
      /*
        Unroll clear of <= 36 bytes (72 if 8byte sizes)
        We know that contents have an odd number of
        size_t-sized words; minimally 3.
      */

      d = (size_t*)mem;
      clearsize = chunksize(p) - SIZE_SZ;
      nclears = clearsize / sizeof(size_t);
      assert(nclears >= 3);

      if (nclears > 9)
        MALLOC_ZERO(d, clearsize);

      else {
        *(d+0) = 0;
        *(d+1) = 0;
        *(d+2) = 0;
        if (nclears > 4) {
          *(d+3) = 0;
          *(d+4) = 0;
          if (nclears > 6) {
            *(d+5) = 0;
            *(d+6) = 0;
            if (nclears > 8) {
              *(d+7) = 0;
              *(d+8) = 0;
            }
          }
        }
      }
    }
  }
  return mem;
}

/*
  ------------------------- malloc_usable_size -------------------------
*/

size_t mUSABLe(void* mem)
{
  mchunkptr p;
  if (mem != 0) {
    p = mem2chunk(mem);
    if (chunk_is_mmapped(p))
      return chunksize(p) - 3*SIZE_SZ; /* updated size for adding arena_ptr */
    else if (inuse(p))
      return chunksize(p) - 2*SIZE_SZ; /* updated size for adding arena_ptr */
  }
  return 0;
}

/*
  ------------------------------ mallinfo ------------------------------
*/

struct mallinfo mALLINFo(zy_mm_mstate_t *av)
{
  struct mallinfo mi;
  int i;
  mbinptr b;
  mchunkptr p;
  size_t avail;
  size_t fastavail;
  int nblocks;
  int nfastblocks;

  /* Ensure initialization */
  if (av->top == 0)  zy_mm_malloc_consolidate(av);

  check_malloc_state(av);

  /* Account for top */
  avail = chunksize(av->top);
  nblocks = 1;  /* top always exists */

  /* traverse fastbins */
  nfastblocks = 0;
  fastavail = 0;

  for (i = 0; i < NFASTBINS; ++i) {
    for (p = av->fastbins[i]; p != 0; p = p->fd) {
      ++nfastblocks;
      fastavail += chunksize(p);
    }
  }

  avail += fastavail;

  /* traverse regular bins */
  for (i = 1; i < NBINS; ++i) {
    b = bin_at(av, i);
    for (p = last(b); p != b; p = p->bk) {
      ++nblocks;
      avail += chunksize(p);
    }
  }

  mi.smblks = nfastblocks;
  mi.ordblks = nblocks;
  mi.fordblks = avail;
  mi.uordblks = av->system_mem - avail;
  mi.arena = av->system_mem;
  mi.fsmblks = fastavail;
  mi.keepcost = chunksize(av->top);
  return mi;
}

/* ---------- description of unimplemented Internal routines ------------ */
/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
void*  public_cALLOc(struct zy_mm_mstate_t *ar_ptr, size_t, size_t);

/*
  valloc(size_t n);
  Equivalent to memalign(pagesize, n), where pagesize is the page
  size of the system. If the pagesize is unknown, 4096 is used.
*/
void*  public_vALLOc(size_t);

/*
  mallopt(int parameter_number, int parameter_value)
  Sets tunable parameters The format is to provide a
  (parameter-number, parameter-value) pair.  mallopt then sets the
  corresponding parameter to the argument value if it can (i.e., so
  long as the value is meaningful), and returns 1 if successful else
  0.  SVID/XPG/ANSI defines four standard param numbers for mallopt,
  normally defined in malloc.h.  Only one of these (M_MXFAST) is used
  in this malloc. The others (M_NLBLKS, M_GRAIN, M_KEEP) don't apply,
  so setting them has no effect. But this malloc also supports four
  other options in mallopt. See below for details.  Briefly, supported
  parameters are as follows (listed defaults are for "typical"
  configurations).

  Symbol            param #   default    allowed param values
  M_MXFAST          1         64         0-80  (0 disables fastbins)
  M_TRIM_THRESHOLD -1         128*1024   any   (-1U disables trimming)
  M_TOP_PAD        -2         0          any
  M_MMAP_THRESHOLD -3         128*1024   any   (or 0 if no MMAP support)
  M_MMAP_MAX       -4         65536      any   (0 disables use of mmap)
*/
int      public_mALLOPt(int, int);

/*
  mallinfo()
  Returns (by copy) a struct containing various summary statistics:

  arena:     current total non-mmapped bytes allocated from system
  ordblks:   the number of free chunks
  smblks:    the number of fastbin blocks (i.e., small chunks that
               have been freed but not use resused or consolidated)
  hblks:     current number of mmapped regions
  hblkhd:    total bytes held in mmapped regions
  usmblks:   the maximum total allocated space. This will be greater
                than current total if trimming has occurred.
  fsmblks:   total bytes held in fastbin blocks
  uordblks:  current total allocated space (normal or mmapped)
  fordblks:  total free space
  keepcost:  the maximum number of bytes that could ideally be released
               back to system via malloc_trim. ("ideally" means that
               it ignores page restrictions etc.)

  Because these fields are ints, but internal bookkeeping may
  be kept as longs, the reported values may wrap around zero and
  thus be inaccurate.
*/
struct mallinfo public_mALLINFo(void);

/*
  independent_calloc(size_t n_elements, size_t element_size, void* chunks[]);

  independent_calloc is similar to calloc, but instead of returning a
  single cleared space, it returns an array of pointers to n_elements
  independent elements that can hold contents of size elem_size, each
  of which starts out cleared, and can be independently freed,
  realloc'ed etc. The elements are guaranteed to be adjacently
  allocated (this is not guaranteed to occur with multiple callocs or
  mallocs), which may also improve cache locality in some
  applications.

  The "chunks" argument is optional (i.e., may be null, which is
  probably the most typical usage). If it is null, the returned array
  is itself dynamically allocated and should also be freed when it is
  no longer needed. Otherwise, the chunks array must be of at least
  n_elements in length. It is filled in with the pointers to the
  chunks.

  In either case, independent_calloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and "chunks"
  is null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be individually freed when it is no longer
  needed. If you'd like to instead be able to free all at once, you
  should instead use regular calloc and assign pointers into this
  space to represent elements.  (In this case though, you cannot
  independently free elements.)

  independent_calloc simplifies and speeds up implementations of many
  kinds of pools.  It may also be useful when constructing large data
  structures that initially have a fixed number of fixed-sized nodes,
  but the number is not known at compile time, and some of the nodes
  may later need to be freed. For example:

  struct Node { int item; struct Node* next; };

  struct Node* build_list() {
    struct Node** pool;
    int n = read_number_of_nodes_needed();
    if (n <= 0) return 0;
    pool = (struct Node**)(independent_calloc(n, sizeof(struct Node), 0);
    if (pool == 0) die();
    // organize into a linked list...
    struct Node* first = pool[0];
    for (i = 0; i < n-1; ++i)
      pool[i]->next = pool[i+1];
    free(pool);     // Can now free the array (or not, if it is needed later)
    return first;
  }
*/
void** public_iCALLOc(size_t, size_t, void**);

/*
  independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);

  independent_comalloc allocates, all at once, a set of n_elements
  chunks with sizes indicated in the "sizes" array.    It returns
  an array of pointers to these elements, each of which can be
  independently freed, realloc'ed etc. The elements are guaranteed to
  be adjacently allocated (this is not guaranteed to occur with
  multiple callocs or mallocs), which may also improve cache locality
  in some applications.

  The "chunks" argument is optional (i.e., may be null). If it is null
  the returned array is itself dynamically allocated and should also
  be freed when it is no longer needed. Otherwise, the chunks array
  must be of at least n_elements in length. It is filled in with the
  pointers to the chunks.

  In either case, independent_comalloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and chunks is
  null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be individually freed when it is no longer
  needed. If you'd like to instead be able to free all at once, you
  should instead use a single regular malloc, and assign pointers at
  particular offsets in the aggregate space. (In this case though, you
  cannot independently free elements.)

  independent_comallac differs from independent_calloc in that each
  element may have a different size, and also that it does not
  automatically clear elements.

  independent_comalloc can be used to speed up allocation in cases
  where several structs or objects must always be allocated at the
  same time.  For example:

  struct Head { ... }
  struct Foot { ... }

  void send_message(char* msg) {
    int msglen = strlen(msg);
    size_t sizes[3] = { sizeof(struct Head), msglen, sizeof(struct Foot) };
    void* chunks[3];
    if (independent_comalloc(3, sizes, chunks) == 0)
      die();
    struct Head* head = (struct Head*)(chunks[0]);
    char*        body = (char*)(chunks[1]);
    struct Foot* foot = (struct Foot*)(chunks[2]);
    // ...
  }

  In general though, independent_comalloc is worth using only for
  larger values of n_elements. For small values, you probably won't
  detect enough difference from series of malloc calls to bother.

  Overuse of independent_comalloc can increase overall memory usage,
  since it cannot reuse existing noncontiguous small chunks that
  might be available for some of the elements.
*/
void** public_iCOMALLOc(size_t, size_t*, void**);

/*
  pvalloc(size_t n);
  Equivalent to valloc(minimum-page-that-holds(n)), that is,
  round up n to nearest pagesize.
 */
void*  public_pVALLOc(size_t);

/*
  malloc_trim(size_t pad);

  If possible, gives memory back to the system (via negative
  arguments to sbrk) if there is unused memory at the `high' end of
  the malloc pool. You can call this after freeing large blocks of
  memory to potentially reduce the system-level memory requirements
  of a program. However, it cannot guarantee to reduce memory. Under
  some allocation patterns, some large free blocks of memory will be
  locked between two used chunks, so they cannot be given back to
  the system.

  The `pad' argument to malloc_trim represents the amount of free
  trailing space to leave untrimmed. If this argument is zero,
  only the minimum amount of memory to maintain internal data
  structures will be left (one page or less). Non-zero arguments
  can be supplied to maintain enough trailing space to service
  future expected allocations without having to re-obtain memory
  from the system.

  Malloc_trim returns 1 if it actually released any memory, else 0.
  On systems that do not support "negative sbrks", it will always
  rreturn 0.
*/
int      public_mTRIm(size_t);

/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);

*/
size_t   public_mUSABLe(void*);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.
*/
void     public_mSTATs(void);

/*
  malloc_get_state(void);

  Returns the state of all malloc variables in an opaque data
  structure.
*/
void*  public_gET_STATe(void);

/*
  malloc_set_state(void* state);

  Restore the state of all malloc variables from data obtained with
  malloc_get_state().
*/
int      public_sET_STATe(void*);

/* ------------------------------------------------------------
History:

[see ftp://g.oswego.edu/pub/misc/malloc.c for the history of dlmalloc]

*/
