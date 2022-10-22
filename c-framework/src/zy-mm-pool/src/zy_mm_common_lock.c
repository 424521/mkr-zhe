#include <pthread.h>

int zy_mm_common_spin_init(pthread_spinlock_t *lock)
{
	return pthread_spin_init(lock, PTHREAD_PROCESS_SHARED);
}

int zy_mm_common_spin_lock(pthread_spinlock_t *lock)
{
	return pthread_spin_lock(lock);
}

int zy_mm_common_spin_tyrlock(pthread_spinlock_t *lock)
{
	return pthread_spin_trylock(lock);
}

int zy_mm_common_spin_unlock(pthread_spinlock_t *lock)
{
	return pthread_spin_unlock(lock);
}

int zy_mm_common_spin_destroy(pthread_spinlock_t *lock)
{
	return pthread_spin_destroy(lock);
}
