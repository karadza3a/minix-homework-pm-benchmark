#include <sys/cdefs.h>
#include "namespace.h"
#include <lib.h>

#include <string.h>
#include <unistd.h>

int start_pm_benchmark(int masks){
    message m;
    m.m1_i1 = masks;
    int e = _syscall(PM_PROC_NR, PM_START_BNCH, &m);
    return e;
}

int stop_pm_benchmark(int masks){
    message m;
    m.m1_i1 = masks;
    int e = _syscall(PM_PROC_NR, PM_STOP_BNCH, &m);
    return e;
}