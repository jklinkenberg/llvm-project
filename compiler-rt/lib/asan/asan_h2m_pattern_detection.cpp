#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <algorithm>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <sstream>
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

typedef struct h2m_pd_phase_t {
    std::string name;
    double ts;
    std::string call_site;
} h2m_pd_phase_t;

typedef struct h2m_pd_base_allocation_t {
    int id;
    void *ptr;
    size_t size;
    size_t dt_size;
    unsigned long range_start;
    unsigned long range_end;
    double ts_alloc;
    double ts_free;
    std::string call_site;
} h2m_pd_base_allocation_t;

typedef struct h2m_pd_entry_t {
    double ts;
    pid_t tid;
    void *ptr;
    size_t size;
    bool is_write;
} h2m_pd_entry_t;

typedef struct h2m_pd_thread_data_t {
    pid_t os_thread_id;
    int ctr_sampling;
    std::vector<h2m_pd_entry_t> mem_accesses;
} h2m_pd_thread_data_t;

typedef struct h2m_pd_stack_trace_t {
    std::vector<void*>          list_trace_ptr;
    std::vector<std::string>    list_loc;
} h2m_pd_stack_trace_t;

// FIXME: might need to use rw_lock if amount of data recorded grows too much
std::mutex                              mtx_allocs;
std::vector<h2m_pd_base_allocation_t>   list_allocs;
int has_allocs = 0;

std::mutex                              mtx_phases;
std::vector<h2m_pd_phase_t>             list_phases;

// thread handling
int global_num_threads;
std::atomic<int>                        __id_counter_alloc(0);
std::atomic<int>                        __id_counter_threads(0);
__thread int                            __h2m_pd_gtid = -1;
h2m_pd_thread_data_t*                   __thread_data = nullptr;

int sampling_factor = 1; // default: record every sample
int h2m_pd_is_initialized = 0;

void string_split(const std::string& str, std::vector<std::string>& list, char delim) {
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delim)) {
        list.push_back(token);
    }
}

void exec(const char* cmd, char* buffer) {
    FILE *fp;
    char buf[255];
    /* Open the command for reading. */
    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        return;
    }
    /* Read the output a line at a time - output it. */
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        strcat(buffer, buf);
    }
    /* close */
    pclose(fp);
}

std::string get_current_exe_name() {
    char exe[1024];
    int ret;
    ret = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if(ret ==-1) {
        fprintf(stderr,"ERRORRRRR\n");
        exit(1);
    }
    exe[ret] = 0;
    std::string exe_str(exe);
    std::vector<std::string> vec;
    string_split(exe_str, vec, '/');

    return vec[vec.size()-1];
}

void get_stack_trace(h2m_pd_stack_trace_t* st) {
    st->list_loc.clear();
    st->list_trace_ptr.clear();

    void *trace[16];
    // char **messages = (char **)NULL;
    int i, trace_size = 0;

    trace_size  = backtrace(trace, 16);
    // messages    = backtrace_symbols(trace, trace_size);
    std::string exe_name = get_current_exe_name();
    
    // printf("[bt] Execution path:\n");
    for (i = 0; i < trace_size; ++i) {
        // printf("[bt] #%d %s\n", i, messages[i]);        
        char syscom[256];
        sprintf(syscom,"addr2line %p -e %s", trace[i], exe_name.c_str()); //last parameter is the name of this app

        char buffer[1024];
        buffer[0] = 0;
        exec(syscom, buffer);

        std::string call_site(buffer);
        call_site.erase(std::remove(call_site.begin(), call_site.end(), '\n'), call_site.end());

        st->list_loc.push_back(call_site);
        st->list_trace_ptr.push_back(trace[i]);
    }
}

double h2m_pd_mysecond() {
    struct timeval tp;
    struct timezone tzp;
    gettimeofday(&tp,&tzp);
    return ( (double) tp.tv_sec + (double) tp.tv_usec * 1.e-6 );
}

inline int h2m_pd_get_gtid() {
    if(__h2m_pd_gtid != -1) {
        return __h2m_pd_gtid;
    }
    __h2m_pd_gtid = __id_counter_threads++;
#if H2M_PD_DEBUG
    fprintf(stderr, "Current thread = %d\n", __h2m_pd_gtid);
#endif // H2M_PD_DEBUG
    __thread_data[__h2m_pd_gtid].os_thread_id = gettid();
    return __h2m_pd_gtid;
}

int h2m_pd_init(int n_threads) {
    fprintf(stderr, "Initialized with %d threads\n", n_threads);
    global_num_threads  = n_threads;
    __thread_data       = new h2m_pd_thread_data_t[n_threads];

    for(int i = 0; i < n_threads; i++) {
        __thread_data[i].mem_accesses.reserve(20000000);
        __thread_data[i].ctr_sampling = 0;
    }
    
    mtx_allocs.lock();
    list_allocs.clear();
    has_allocs = 0;
    mtx_allocs.unlock();

    mtx_phases.lock();
    list_phases.clear();
    mtx_phases.unlock();

    char *sf = std::getenv("H2M_PD_SAMPLING_FACTOR");
    if(sf) {
        sampling_factor = std::atoi(sf);
    }

    h2m_pd_is_initialized = 1;
    return H2M_PD_SUCCESS;
}

int h2m_pd_register_allocation(void *ptr, size_t size, size_t dt_size) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_FAILURE;
    }

    h2m_pd_base_allocation_t e;
    e.id            = __id_counter_alloc++;
    e.ptr           = ptr;
    e.size          = size;
    e.dt_size       = dt_size;
    e.range_start   = (unsigned long) ptr;
    e.range_end     = e.range_start + size;
    e.ts_alloc      = h2m_pd_mysecond();
    e.ts_free       = -1;

    // get call site
    h2m_pd_stack_trace_t* st = new h2m_pd_stack_trace_t();
    get_stack_trace(st);
    e.call_site  = st->list_loc.size() < 4 ? "" : std::string(st->list_loc[3]);
#if H2M_PD_DEBUG
    printf("New allocation: %p (%ld) -> %s\n", e.ptr, e.range_start, e.call_site.c_str());
#endif
    delete st;

    mtx_allocs.lock();
    list_allocs.push_back(e);
    if (!has_allocs) {
        has_allocs = 1;
    }
    mtx_allocs.unlock();
    return H2M_PD_SUCCESS;
}

int h2m_pd_unregister_allocation(void *ptr) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_FAILURE;
    }
    
    mtx_allocs.lock();
    for (h2m_pd_base_allocation_t &e : list_allocs) {
        if(ptr == e.ptr && e.ts_free == -1) {
            e.ts_free = h2m_pd_mysecond();
            mtx_allocs.unlock();
            return H2M_PD_SUCCESS;
        }
    }
    mtx_allocs.unlock();
    return H2M_PD_FAILURE;
}

int h2m_pd_add_mem_access(void *ptr, size_t size, int is_write) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_FAILURE;
    }
    if (!has_allocs) {
        return H2M_PD_SUCCESS;
    }

    int gtid = h2m_pd_get_gtid();

    if (sampling_factor != 1) {
        if(__thread_data[gtid].ctr_sampling % sampling_factor == 0) {
            __thread_data[gtid].ctr_sampling = 1;
        } else {
            __thread_data[gtid].ctr_sampling++;
            return H2M_PD_SUCCESS;
        }
    }

    h2m_pd_entry_t e;
    e.ts        = h2m_pd_mysecond();
    e.tid       = __thread_data[gtid].os_thread_id;
    e.ptr       = ptr;
    e.size      = size;
    e.is_write  = is_write;

    __thread_data[gtid].mem_accesses.push_back(e);
    return H2M_PD_SUCCESS;
}

int h2m_pd_new_phase(const char* name) {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_FAILURE;
    }

    h2m_pd_phase_t p;
    p.name      = std::string(name);
    p.ts        = h2m_pd_mysecond();

    // get call site
    h2m_pd_stack_trace_t* st = new h2m_pd_stack_trace_t();
    get_stack_trace(st);
    p.call_site  = st->list_loc.size() < 4 ? "" : std::string(st->list_loc[3]);
#if H2M_PD_DEBUG
    printf("New phase: %s (%f) -> %s\n", p.name.c_str(), p.ts, p.call_site.c_str());
#endif
    delete st;

    mtx_phases.lock();
    list_phases.push_back(p);
    mtx_phases.unlock();

    return H2M_PD_SUCCESS;
}

int h2m_pd_access_is_registered(h2m_pd_entry_t acc) {
    unsigned long start = (unsigned long) acc.ptr;
    unsigned long end   = start + acc.size;

    mtx_allocs.lock();
    for (h2m_pd_base_allocation_t &e : list_allocs) {
        if( start >= e.range_start && start <= e.range_end &&
            end >= e.range_start && end <= e.range_end) {

            if (acc.ts >= e.ts_alloc && (e.ts_free == -1 || acc.ts <= e.ts_free)) {
                mtx_allocs.unlock();
                return 1;
            }
        }
    }
    mtx_allocs.unlock();
    return 0;
}

// Assumption: Only called in finalize from serial region (no thread safety)
h2m_pd_base_allocation_t* h2m_pd_find_registered_alloc(h2m_pd_entry_t acc) {
    unsigned long start = (unsigned long) acc.ptr;
    unsigned long end   = start + acc.size;

    for (h2m_pd_base_allocation_t &e : list_allocs) {
        if( start >= e.range_start && start <= e.range_end &&
            end >= e.range_start && end <= e.range_end) {
            
            if (acc.ts >= e.ts_alloc && (e.ts_free == -1 || acc.ts <= e.ts_free)) {
                return &e;
            }
        }
    }
    return nullptr;
}

std::map<int, std::vector<h2m_pd_entry_t>> get_accesses_per_allocation () {
    // init mapping lists
    std::map<int, std::vector<h2m_pd_entry_t>> mapping;
    for(h2m_pd_base_allocation_t &alloc : list_allocs) {
        mapping[alloc.id] = std::vector<h2m_pd_entry_t>();
    }

    // loop through memory accesses for every thread
    for (int i = 0; i < global_num_threads; i++) {
        for (h2m_pd_entry_t &acc : __thread_data[i].mem_accesses) {
            h2m_pd_base_allocation_t *found = h2m_pd_find_registered_alloc(acc);
            if(found) {
                mapping[found->id].push_back(acc);
            }
        }
    }
    return mapping;
}

void print_global_stats() {
    printf("H2M PD - Overall # of registered memory allocation: %lld\n", list_allocs.size());
    printf("H2M PD - Overall # of phase transitions: %lld\n", list_phases.size());
#if H2M_PD_DEBUG
    for (auto &al : list_allocs) {
        printf("H2M PD - Registered Alloc: %p with size=%lld\n", al.ptr, al.size);
    }
#endif // H2M_PD_DEBUG
    
    unsigned long n_accesses            = 0;
    unsigned long n_accesses_relevant   = 0;
    
    for (int i = 0; i < global_num_threads; i++) {
        n_accesses += __thread_data[i].mem_accesses.size();
        for (h2m_pd_entry_t &acc : __thread_data[i].mem_accesses) {
            if(h2m_pd_access_is_registered(acc)) {
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

void output_accesses_per_allocation(std::map<int, std::vector<h2m_pd_entry_t>> mapping) {
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
        char str_id[4];
        snprintf (str_id, 4, "%03d", a.id);
        std::string tmp_path = std::string(pathname) + "/alloc_" + std::string(str_id) + ".txt";
        // std::string tmp_path = std::string(pathname) + "/alloc_" + std::to_string(a.id) + ".txt";
        std::ofstream tmp_file(tmp_path);
        if(!tmp_file.is_open()) {
            fprintf(stderr, "WARNING: Could not open/write file %s.\n", tmp_path.c_str());
            continue;
        }

        // write phase transition information
        tmp_file    << "PhaseName;CallSite;TimeStamp" << std::endl;
        for(h2m_pd_phase_t &p : list_phases) {
            tmp_file    << p.name << ";" << p.call_site << ";" << std::to_string(p.ts) << std::endl;
        }

        // write meta information for current allocation
        tmp_file    << "BaseAddress;" << a.ptr << ";"
                    << "Size;" << a.size << ";" 
                    << "DataTypeSize;" << a.dt_size << ";"
                    << "RangeStart;" << std::to_string(a.range_start) << ";"
                    << "RangeEnd;" << std::to_string(a.range_end) << ";"
                    << "TsAlloc;" << std::to_string(a.ts_alloc) << ";"
                    << "TsFree;" << std::to_string(a.ts_free) << ";"
                    << "SamplingFactor;" << std::to_string(sampling_factor) << ";"
                    << "CallSite;" << a.call_site
                    << std::endl;

        // write header
        tmp_file << "TimeStamp;ThreadId;Address;AddressLong;Size;IsWrite" << std::endl;

        std::vector<h2m_pd_entry_t> &accs = mapping[a.id];
#if H2M_PD_DEBUG
        printf("H2M PD - Mem Accesses for Registered Alloc: %p with size=%lld\n", a.ptr, a.size);
#endif // H2M_PD_DEBUG
        for(h2m_pd_entry_t &e : accs) {
            tmp_file    << std::to_string(e.ts) << ";"
                        << (long)e.tid << ";"
                        << e.ptr << ";"
                        << (unsigned long)e.ptr << ";"
                        << e.size << ";"
                        << e.is_write << std::endl;
#if H2M_PD_DEBUG
                printf("   H2M PD - Access: ts=%s, tid=%lld, ptr=%p, size=%lld, is_write=%d\n", std::to_string(e.ts), (long)e.tid, e.ptr, e.size, e.is_write);
#endif // H2M_PD_DEBUG
        }
        tmp_file.close();
    }
}

int h2m_pd_finalize() {
    if (!h2m_pd_is_initialized) {
        return H2M_PD_FAILURE;
    }

    // ============================================================
    // ===== get mapping per allocation
    // ============================================================
    std::map<int, std::vector<h2m_pd_entry_t>> acc_per_alloc = get_accesses_per_allocation();

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
    h2m_pd_is_initialized = 0;
    return H2M_PD_SUCCESS;
}