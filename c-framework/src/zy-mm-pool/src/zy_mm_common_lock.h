#ifndef __ZY_MM_COMMON_LOCK_H__
#define __ZY_MM_COMMON_LOCK_H__
#include <pthread.h>
int zy_mm_common_spin_init(pthread_spinlock_t *lock);
int zy_mm_common_spin_lock(pthread_spinlock_t *lock);
int zy_mm_common_spin_tyrlock(pthread_spinlock_t *lock);
int zy_mm_common_spin_unlock(pthread_spinlock_t *lock);
int zy_mm_common_spin_destory(pthread_spinlock_t *lock);
#endif