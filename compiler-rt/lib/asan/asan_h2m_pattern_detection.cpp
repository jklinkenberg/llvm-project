#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "asan_h2m_pattern_detection.h"

#ifndef H2M_PD_DEBUG
#define H2M_PD_DEBUG 0
#endif

typedef struct h2m_pd_base_allocation_t {
    void *ptr;
    size_t size;
    unsigned long range_start;
    unsigned long range_end;
    std::string name;
    size_t dt_size;
} h2m_pd_base_allocation_t;

typedef struct h2m_pd_entry_t {
    double ts;
    pid_t tid;
    void *ptr;
    size_t size;
    bool is_write;
} h2m_pd_entry_t;

typedef struct h2m_pd_thread_data_t {
    int os_thread_id;
    std::vector<h2m_pd_entry_t> mem_accesses;
} h2m_pd_thread_data_t;

// FIXME: might need to use rw_lock if amount of data recorded grows too much
std::mutex                              mtx_allocs;
std::vector<h2m_pd_base_allocation_t>   list_allocs;

// thread handling
int global_num_threads;
std::atomic<int>                        __thread_counter(0);
__thread int                            __h2m_pd_gtid = -1;
h2m_pd_thread_data_t*                   __thread_data = nullptr;

int h2m_pd_is_initialized = 0;

double h2m_pd_mysecond() {
    struct timeval tp;
    struct timezone tzp;
    int i;

    i = gettimeofday(&tp,&tzp);
    return ( (double) tp.tv_sec + (double) tp.tv_usec * 1.e-6 );
}

int h2m_pd_get_gtid() {
    if(__h2m_pd_gtid != -1) {
        return __h2m_pd_gtid;
    }
    __h2m_pd_gtid = __thread_counter++;
#if H2M_PD_DEBUG
    fprintf(stderr, "Current thread = %d\n", __h2m_pd_gtid);
#endif // H2M_PD_DEBUG
    __thread_data[__h2m_pd_gtid].os_thread_id = syscall(SYS_gettid);
    return __h2m_pd_gtid;
}

int h2m_pd_init(int n_threads) {
    fprintf(stderr, "Initialized with %d threads\n", n_threads);
    global_num_threads  = n_threads;
    __thread_data       = new h2m_pd_thread_data_t[n_threads];
    
    mtx_allocs.lock();
    list_allocs.clear();
    mtx_allocs.unlock();
    h2m_pd_is_initialized = 1;
    return H2M_PD_SUCCESS;
}

int h2m_pd_register_allocation(void *ptr, size_t size, const char* name, size_t dt_size) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_SUCCESS;
    }

    h2m_pd_base_allocation_t e;
    e.ptr           = ptr;
    e.size          = size;
    e.range_start   = (unsigned long) ptr;
    e.range_end     = e.range_start + size;
    e.name          = std::string(name);
    e.dt_size       = dt_size;

    mtx_allocs.lock();
    list_allocs.push_back(e);
    mtx_allocs.unlock();
    return H2M_PD_SUCCESS;
}

int h2m_pd_add_mem_access(void *ptr, size_t size, int is_write) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_SUCCESS;
    }

    h2m_pd_entry_t e;
    e.ts        = h2m_pd_mysecond();
    e.tid       = gettid();
    e.ptr       = ptr;
    e.size      = size;
    e.is_write  = is_write;

    int gtid = h2m_pd_get_gtid();
    __thread_data[gtid].mem_accesses.push_back(e);
    return H2M_PD_SUCCESS;
}

int h2m_pd_access_is_registered(unsigned long start, unsigned long end) {
    mtx_allocs.lock();
    for (h2m_pd_base_allocation_t &e : list_allocs) {
        if( start >= e.range_start &&
            start <= e.range_end &&
            end >= e.range_start &&
            end <= e.range_end) {

            mtx_allocs.unlock();
            return 1;
        }
    }
    mtx_allocs.unlock();
    return 0;
}

// Assumption: Only called in finalize from serial region (no thread safety)
h2m_pd_base_allocation_t* h2m_pd_find_registered_alloc(unsigned long start, unsigned long end) {
    for (h2m_pd_base_allocation_t &e : list_allocs) {
        if( start >= e.range_start &&
            start <= e.range_end &&
            end >= e.range_start &&
            end <= e.range_end) {
            return &e;
        }
    }
    return nullptr;
}

std::map<void*, std::vector<h2m_pd_entry_t>> get_accesses_per_allocation () {
    std::map<void*, std::vector<h2m_pd_entry_t>> mapping;
    for(h2m_pd_base_allocation_t &a : list_allocs) {
        mapping[a.ptr] = std::vector<h2m_pd_entry_t>();
    }

    for (int i = 0; i < global_num_threads; i++) {
        for (h2m_pd_entry_t &acc : __thread_data[i].mem_accesses) {
            unsigned long tmp_s = (unsigned long) acc.ptr;
            unsigned long tmp_e = tmp_s + acc.size;
            h2m_pd_base_allocation_t *found = h2m_pd_find_registered_alloc(tmp_s, tmp_e);
            if(found) {
                mapping[found->ptr].push_back(acc);
            }
        }
    }
    return mapping;
}

void print_global_stats() {
    printf("H2M PD - Overall # of memory allocation: %lld\n", list_allocs.size());
#if H2M_PD_DEBUG
    for (auto &al : list_allocs) {
        printf("H2M PD - Registered Alloc: %p with size=%lld\n", al.ptr, al.size);
    }
#endif // H2M_PD_DEBUG
    
    unsigned long n_accesses = 0;
    unsigned long n_accesses_relevant = 0;
    
    for (int i = 0; i < global_num_threads; i++) {
        n_accesses += __thread_data[i].mem_accesses.size();
        for (h2m_pd_entry_t &acc : __thread_data[i].mem_accesses) {
            unsigned long tmp_s = (unsigned long) acc.ptr;
            unsigned long tmp_e = tmp_s + acc.size;
            if(h2m_pd_access_is_registered(tmp_s, tmp_e)) {
                n_accesses_relevant++;
#if H2M_PD_DEBUG
                printf("H2M PD - Mem Access: ts=%f, tid=%lld (check=%d, gtid=%d), ptr=%p, size=%lld, is_write=%d\n", acc.ts, (long)acc.tid, __thread_data[i].os_thread_id, i, acc.ptr, acc.size, acc.is_write);
#endif // H2M_PD_DEBUG
            }
        }
    }

    printf("H2M PD - Overall # of memory accesses: %lld\n", n_accesses);
    printf("H2M PD - Overall # of relevant memory accesses: %lld\n\n", n_accesses_relevant);
}

void output_accesses_per_allocation(std::map<void*, std::vector<h2m_pd_entry_t>> mapping) {
    // get path from environment variable to decide whether to write to files
    char *pathname = std::getenv("H2M_PD_OUT_DIR");
    if(!pathname) {
        return;
    }

    // check whether directory exists
    struct stat info;
    if (stat(pathname, &info) != 0) {
        fprintf(stderr, "WARNING: cannot access %s\n", pathname);
        return;
    } else if (info.st_mode & S_IFDIR) {
        //printf( "%s is a directory\n", pathname );
    } else {
        fprintf(stderr, "WARNING: %s is not a directory\n", pathname);
        return;
    }

    for(h2m_pd_base_allocation_t &a : list_allocs) {
        std::string tmp_path = std::string(pathname) + "/" + a.name + ".txt";
        std::ofstream tmp_file(tmp_path);
        if(!tmp_file.is_open()) {
            fprintf(stderr, "WARNING: Could not open/write file %s.\n", tmp_path.c_str());
            continue;
        }

        // write meta information for current allocation
        tmp_file    << "Address;" << a.ptr << ";"
                    << "Size;" << a.size << ";" 
                    << "RangeStart;" << a.range_start << ";"
                    << "RangeEnd;" << a.range_end << ";"
                    << "DataTypeSize;" << a.dt_size << ";"
                    << std::endl;

        // write header
        tmp_file << "TimeStamp;ThreadId;Address;AddressLong;Size;IsWrite" << std::endl;

        std::vector<h2m_pd_entry_t> &accs = mapping[a.ptr];
#if H2M_PD_DEBUG
        printf("H2M PD - Mem Accesses for Registered Alloc: %p with size=%lld\n", a.ptr, a.size);
#endif // H2M_PD_DEBUG
        for(h2m_pd_entry_t &e : accs) {
            tmp_file    << e.ts << ";"
                        << (long)e.tid << ";"
                        << e.ptr << ";"
                        << (unsigned long)e.ptr << ";"
                        << e.size << ";"
                        << e.is_write << std::endl;
#if H2M_PD_DEBUG
            printf("   H2M PD - Access: ts=%f, tid=%lld, ptr=%p, size=%lld, is_write=%d\n", e.ts, (long)e.tid, e.ptr, e.size, e.is_write);
#endif // H2M_PD_DEBUG
        }
        tmp_file.close();
    }
}

int h2m_pd_finalize() {
    // ============================================================
    // ===== get mapping per allocation
    // ============================================================
    std::map<void*, std::vector<h2m_pd_entry_t>> acc_per_alloc = get_accesses_per_allocation();

    // ============================================================
    // ===== output
    // ============================================================
    print_global_stats();
    output_accesses_per_allocation(acc_per_alloc);

    // FIXME: Do analysis and recommendation here

    // cleanup
    for (int i = 0; i < global_num_threads; i++) {
        __thread_data[i].mem_accesses.clear();
    }
    delete[] __thread_data;
    list_allocs.clear();
    return H2M_PD_SUCCESS;
}