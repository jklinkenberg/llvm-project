#ifndef __ASAN_H2M_PATTERN_DETECTION_H__
#define __ASAN_H2M_PATTERN_DETECTION_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
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

#ifdef __cplusplus
extern "C" {
#endif

int h2m_pd_init(int n_threads);
int h2m_pd_register_allocation(void *ptr, size_t size, size_t dt_size);
int h2m_pd_unregister_allocation(void *ptr);
int h2m_pd_add_mem_access(void *ptr, size_t size, int is_write);
int h2m_pd_new_phase(const char* name);
int h2m_pd_finalize();

#ifdef __cplusplus
}
#endif
#endif // __ASAN_H2M_PATTERN_DETECTION_H__