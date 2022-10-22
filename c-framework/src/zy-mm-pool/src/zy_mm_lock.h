#ifndef __ZY_MM_LOCK_H__
#define __ZY_MM_LOCK_H__
#include "zy_mm_common_lock.h"

typedef pthread_spinlock_t mutex_t;

//#define MUTEX_INITIALIZER          SG_SPINLOCK_INITIALIAZER
#define mutex_init(m)              zy_mm_common_spin_init(m)
#define mutex_lock(m)              zy_mm_common_spin_lock(m)
#define mutex_trylock(m)           zy_mm_common_spin_tyrlock(m)
#define mutex_unlock(m)            zy_mm_common_spin_unlock(m)
#endif