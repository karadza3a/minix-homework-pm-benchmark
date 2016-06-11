#include <sys/cdefs.h>
#include "namespace.h"
#include <lib.h>

#include <string.h>
#include <unistd.h>

int start_sniffing(char *host, char *filepath){
    message m;
    m.hss_callnr = HSS_START_SNIFFING;
    m.hss_httphost = host;
    m.hss_filepath = filepath;
    m.hss_httphost_len = strlen(host);
    m.hss_filepath_len = strlen(filepath);

    int e = _syscall(PM_PROC_NR, PM_FORWARDTOHSS, &m);
    return e;
}

int stop_sniffing(int id){
    message m;
    m.hss_callnr = HSS_STOP_SNIFFING;
    m.hss_id = id;

    int e = _syscall(PM_PROC_NR, PM_FORWARDTOHSS, &m);
    return e;
}