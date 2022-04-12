#ifndef __ASAN_H2M_PATTERN_DETECTION_H__
#define __ASAN_H2M_PATTERN_DETECTION_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef gettid
#define gettid() ((pid_t)syscall(SYS_gettid))
#endif

typedef enum h2m_pd_result_types_t {
    H2M_PD_SUCCESS      = 0,
    H2M_PD_FAILURE      = 1,
} h2m_pd_result_types_t;

typedef struct h2m_pd_entry_t {
    double ts;
    pid_t tid;
    void *ptr;
    int size;
    bool is_write;
} h2m_pd_entry_t;

typedef struct h2m_pd_base_allocation_t {
    void *ptr;
    int size;
} h2m_pd_base_allocation_t;

int h2m_pd_init();
int h2m_pd_register_allocation(void *ptr, size_t size);
int h2m_pd_add_mem_access(void *ptr, int size, bool is_write);
int h2m_pd_finalize();

#endif // __ASAN_H2M_PATTERN_DETECTION_H__