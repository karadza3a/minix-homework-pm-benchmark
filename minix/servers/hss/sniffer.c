#include "inc.h"
#include "sniffer.h"


#include <sys/cdefs.h>
#include <lib.h>

#include <fcntl.h>
#include <stdarg.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

int load_config() {

    char config[1024];

    message m;
    memset(&m, 0, sizeof(m));

    // open the file
    _loadname("/remote.conf", &m);
    m.m_lc_vfs_path.flags = O_RDONLY;
    int fd = (_taskcall(VFS_PROC_NR, VFS_OPEN, &m));
    if (fd < 0) {
        printf(" oooopss fd  %d\n", fd);
        return -1;
    }

    // read file
    memset(&m, 0, sizeof(m));
    m.m_lc_vfs_readwrite.fd = fd;
    m.m_lc_vfs_readwrite.buf = (vir_bytes) config;
    m.m_lc_vfs_readwrite.len = 1024;
    int r = (_taskcall(VFS_PROC_NR, VFS_READ, &m));

    int i = 0, row = 0, j = 0;
    while (1) {
        while (j != 1023) {
            if (config[j] == 10 || config[j] == 13)
                break;
            ++j;
        }
        config[j] = 0;

        printf(" > %s\n", config + i);

        if (row == 2)
            strcpy(remote_config.username, config + i);
        else if (row == 3) {
            strcpy(remote_config.password, config + i);
            break;
        }

        ++row;
        i = j;

        while (1) {
            ++j;
            ++i;
            if (config[j] != 10 && config[j] != 13)
                break;
        }
    }

    // close the file
    memset(&m, 0, sizeof(m));
    m.m_lc_vfs_readwrite.fd = fd;
    r = (_taskcall(VFS_PROC_NR, VFS_CLOSE, &m));
    remote_config.loaded = 1;
    return r;
}

/*===========================================================================*
 *				do_start_sniffing				     *
 *===========================================================================*/
int do_check(message *m_ptr) {
    int r;
    if (!remote_config.loaded) {
        r = load_config();
        if (r != OK) {
            printf(" oooopss lc %d\n", r);
            return -1;
        }
    }

    const int BUFF_SIZE = 1024;
    char username[BUFF_SIZE];
    char password[BUFF_SIZE];

    r = sys_datacopy(
            m_ptr->m_source, (vir_bytes) m_ptr->hss_username,
            HSS_PROC_NR, (vir_bytes) username,
            BUFF_SIZE * sizeof(char));

    if (r != OK) {
        printf(" oooopss dc1 %d\n", r);
        return -1;
    }

    r = sys_datacopy(
            m_ptr->m_source, (vir_bytes) m_ptr->hss_password,
            HSS_PROC_NR, (vir_bytes) password,
            BUFF_SIZE * sizeof(char));
    if (r != OK) {
        printf(" oooopss dc2 %d\n", r);
        return -1;
    }

    if (strcmp(username, remote_config.username) == 0 && strcmp(password, remote_config.password) == 0)
        return 0;
    return 1;
}
