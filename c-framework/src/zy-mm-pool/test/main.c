#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include "zy_mm_heap.h"
#include "zy_mm_malloc.h"
#include "list.h"

#define ZY_MM_TEST_POOL_SIZE      (100 * 1024 * 1024)   /* unit: bytes */

#define ZY_MM_TEST_ALIGN(d, a)				(((d) + (a - 1)) & ~(a - 1))

struct zy_mm_person {
    char *name;
    int32_t age;
    char sex[8];
};

struct zy_mm_person_list {
    struct list_head list;
    struct zy_mm_person person;
};

struct zy_mm_shared_info {
    void *mm_pool;
    void *shm_addr;
    struct list_head person_list;
};

void *g_zy_mm_test_shared_addr;
struct zy_mm_shared_info *g_zy_mm_shared_info;
char global_shm_info_name[] = "zy-mm-test-global-info";

void *zy_mm_test_shm_pool_open(const char *name,  size_t size, int flags)
{
	int fd;
	int32_t ret = 0;
	void *ptr;

	if (!name || '\0' == name[0] || 0 == size) {
		printf("invalid parameter.\n");
		return NULL;
	}

	fd = shm_open(name, flags, 0666);
	if (fd < 0) {
		printf("failed to open %s.\n", name);
		return NULL;
	}

	size = ZY_MM_TEST_ALIGN(size, 2 * 1024 * 1024);
	if (flags & O_CREAT) {
		ret = ftruncate(fd, size);
		if (ret == -1) {
			printf("mm, ftruncate(MAP_ANON|MAP_SHARED, %lu) failed, name %s\n", size, name);
			close(fd);
			return NULL;
		}
	}

	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE,
			MAP_SHARED, fd, 0);

	if (ptr == MAP_FAILED) {
		printf("mm, mmap(MAP_ANON|MAP_SHARED, %lu) failed, name %s\n", size, name);
		close(fd);
		return NULL;
	}

	printf("mm, mmap name %s, size %lu, ptr %p\n", name, size, ptr);
	close(fd);

	return ptr;
}

void zy_mm_test_shm_pool_destroy(const char *name, void *addr_t, size_t size)
{
    if (addr_t && size) {
        munmap(addr_t, size);
    }

    shm_unlink(name);

    return;
}

int32_t zy_mm_test_add_person(struct list_head *head, const char *name, int32_t age, const char *sex)
{
    struct zy_mm_person_list *tmp;

    tmp = zy_mm_malloc(g_zy_mm_shared_info->mm_pool, sizeof(*tmp));
    if (NULL == tmp) {
        printf("Failed to malloc memory.\n");
        return -1;
    }

    tmp->person.name = zy_mm_malloc(g_zy_mm_shared_info->mm_pool, strlen(name) + 1);
    if (NULL == tmp->person.name) {
        printf("Failed to malloc name.\n");
        goto err;
    }
    memcpy(tmp->person.name, name, strlen(name));
    tmp->person.name[strlen(name)] = '\0';

    tmp->person.age = age;
    snprintf(tmp->person.sex, sizeof(tmp->person.sex), "%s", sex);

    list_add_tail(&tmp->list, head);

    return 0;

err:
    zy_mm_kfree(g_zy_mm_shared_info->mm_pool, tmp);
    return -1;
}

int32_t zy_mm_test_print_person_list(const char *process_name)
{
    struct zy_mm_person_list *tmp;

    list_for_each_entry(tmp, &g_zy_mm_shared_info->person_list, list) {
        printf("%s print: name: %s, age: %d, sex: %s\n",
                process_name, tmp->person.name, tmp->person.age, tmp->person.sex);
    }

    return 0;
}

int zy_mm_child_mm_use()
{
    int32_t new_cnt = 10, i;
    char name[32];

    printf("i'm child, wait for parent process.\n");
    sleep(5);
    printf("i'm child, print information:\n");
    zy_mm_test_print_person_list("child");
    printf("i'm child. after print information, i'll add new persons.\n");

    for (i = 0; i < new_cnt; i++) {
        snprintf(name, sizeof(name), "child-person%d", i + 1);
        zy_mm_test_add_person(&g_zy_mm_shared_info->person_list, name, i + 1,
                                i % 2 ==0 ? "man" : "woman");
    }
    sleep(5);
    printf("i'm child, print information2:\n");
    zy_mm_test_print_person_list("child");
    printf("i'm child, i'll exit.\n");
    return 0;
}

int32_t zy_mm_parent_mm_use()
{
    int32_t cnt = 10, i;
    char name[32];
    int child_st = 0;

    for (i = 0; i < cnt; i++) {
        snprintf(name, sizeof(name), "parent-person%d", i + 1);
        zy_mm_test_add_person(&g_zy_mm_shared_info->person_list, name, i + 1,
                                i % 2 ==0 ? "man" : "woman");
    }
    sleep(5);
    printf("i'm parent, print information:\n");
    zy_mm_test_print_person_list("parent");
    wait(&child_st);
    printf("all child have exits.\n");
    sleep(5);
    return 0;
}

int zy_mm_test_1()
{
    char pool_name[] = "zy-mm-pool-test";
    void *shm_addr;
    pid_t pid;
    void *mm_pool;

    printf("------------------test1----------\n");
    g_zy_mm_shared_info = zy_mm_test_shm_pool_open(global_shm_info_name,
                                                   sizeof(*global_shm_info_name),
                                                   O_RDWR|O_CREAT);
    if (NULL == g_zy_mm_shared_info) {
        printf("Failed to open %s\n", global_shm_info_name);
    }


    printf("open pool.\n");
    shm_addr = zy_mm_test_shm_pool_open(pool_name, ZY_MM_TEST_POOL_SIZE, O_RDWR|O_CREAT);
    if (NULL == shm_addr) {
        printf("Failed to open pool.\n");
        return 0;
    }

    printf("init mem pool\n");
    mm_pool = zy_mm_init_malloc(shm_addr, ZY_MM_TEST_POOL_SIZE);

    printf("mm pool is %p, shm addr is %p\n", mm_pool, shm_addr);
    g_zy_mm_shared_info->mm_pool = mm_pool;
    g_zy_mm_shared_info->shm_addr = shm_addr;

    INIT_LIST_HEAD(&g_zy_mm_shared_info->person_list);

    pid = fork();
    if (pid < 0) {
        printf("Failed to fork child process.\n");
        return -1;
    } else if (0 == pid) {
        printf("i'm child, shared info addr is %p\n", g_zy_mm_shared_info);
        zy_mm_child_mm_use();
        printf("i'm child, will destory mm pool.\n");
        sleep(20);
        zy_mm_test_shm_pool_destroy(pool_name, g_zy_mm_test_shared_addr, ZY_MM_TEST_POOL_SIZE);
        printf("i'm child, have destory mm pool.\n");
        sleep(10);
    } else {
        printf("i'm parent, shared info addr is %p\n", g_zy_mm_shared_info);
        zy_mm_parent_mm_use();
        printf("i'm parent, will destory mm pool.\n");
        sleep(20);
        printf("i'm parent, before destroy mm pool, print list.\n");
        zy_mm_test_print_person_list("parent");
        zy_mm_test_shm_pool_destroy(pool_name, g_zy_mm_test_shared_addr, ZY_MM_TEST_POOL_SIZE);
        printf("i'm parent, have destory mm pool.\n");
        sleep(10);
    }

    zy_mm_test_shm_pool_destroy(global_shm_info_name, g_zy_mm_shared_info, sizeof(*global_shm_info_name));

    return 0;
}

int main()
{
    zy_mm_test_1();

    return 0;
}