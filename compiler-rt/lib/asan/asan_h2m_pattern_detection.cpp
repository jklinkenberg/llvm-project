#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <list>
#include <vector>
#include <sys/time.h>

#include "asan_h2m_pattern_detection.h"

std::vector<h2m_pd_base_allocation_t>   list_allocs;
std::vector<h2m_pd_entry_t>             list_accesses;

double mysecond() {
    struct timeval tp;
    struct timezone tzp;
    int i;

    i = gettimeofday(&tp,&tzp);
    return ( (double) tp.tv_sec + (double) tp.tv_usec * 1.e-6 );
}

int h2m_pd_init() {
    list_allocs.clear();
    list_accesses.clear();
    return H2M_PD_SUCCESS;
}

int h2m_pd_register_allocation(void *ptr, size_t size) {
    h2m_pd_base_allocation_t e;
    e.ptr   = ptr;
    e.size  = size;
    list_allocs.push_back(e);
    return H2M_PD_SUCCESS;
}

int h2m_pd_add_mem_access(void *ptr, int size, bool is_write) {
    h2m_pd_entry_t e;
    e.ts        = mysecond();
    e.tid       = gettid();
    e.ptr       = ptr;
    e.size      = size;
    e.is_write  = is_write;
    
    // FIXME: needs to be threads save
    // add to list
    list_accesses.push_back(e);
    return H2M_PD_SUCCESS;
}

int h2m_pd_finalize() {
    printf("H2M PD - Size of memory accesses: %lld\n", list_accesses.size());
    // cleanup
    list_allocs.clear();
    list_accesses.clear();
    return H2M_PD_SUCCESS;
}