#include "inc.h"
#include "sniffer.h"


#include <sys/cdefs.h>
#include <lib.h>

#include <fcntl.h>
#include <stdarg.h>
#include <string.h>


#include <stdio.h>
#include <stdlib.h>

/*===========================================================================*
 *				do_start_sniffing				     *
 *===========================================================================*/
int do_start_sniffing(message *m_ptr)
{
	int i, r;
	for (i = 0; i < HSS_MAX_SNIFFERS; ++i) {
		if(sniffing_process[i].active == 0){
			break;
		}
	}

	if(i == HSS_MAX_SNIFFERS)
		return -1;

	r = sys_datacopy(
			m_ptr->hss_source, (vir_bytes)m_ptr->hss_httphost,
			HSS_PROC_NR, (vir_bytes)sniffing_process[i].http_host,
			m_ptr->hss_httphost_len * sizeof(char));

	if(r != OK){
		printf(" ohoj %d\n", r);
		return -1;
	}

	r = sys_datacopy(
			m_ptr->hss_source, (vir_bytes)m_ptr->hss_filepath,
			HSS_PROC_NR, (vir_bytes)sniffing_process[i].filepath,
			m_ptr->hss_filepath_len * sizeof(char));

	if(r != OK){
		printf(" ohoj %d\n", r);
		return -1;
	}

	sniffing_process[i].active = 1;
	return i;
}

/*===========================================================================*
 *				do_getsysinfo				     *
 *===========================================================================*/
int do_getsysinfo(const message *m_ptr)
{
	vir_bytes src_addr;
	size_t length;
	int s;

	src_addr = (vir_bytes)sniffing_process;
	length = sizeof(struct sniffing_process) * HSS_MAX_SNIFFERS;

	if (length != m_ptr->m_lsys_getsysinfo.size)
		return EINVAL;

	if (OK != (s=sys_datacopy(SELF, src_addr,
							  m_ptr->m_source, m_ptr->m_lsys_getsysinfo.where, length))) {
		printf("HSS: copy failed: %d\n", s);
		return s;
	}

	return OK;
}

/*===========================================================================*
 *				do_log_message				     *
 *===========================================================================*/
int do_log_message(message *m_ptr)
{
	message m;

	memset(&m, 0, sizeof(m));
	char *str = "/var/log/hss/x.log";

	_loadname(str, &m);
	m.m_lc_vfs_path.flags = O_APPEND | W_BIT | O_CREAT;

	int fd = (_syscall(VFS_PROC_NR, VFS_CREAT, &m));

	printf("open: %d\n", fd);

	char *buf = "asddasasd";
	int nbytes = 9;
	memset(&m, 0, sizeof(m));

	m.m_lc_vfs_readwrite.fd = fd;
	m.m_lc_vfs_readwrite.buf = (vir_bytes) buf;
	m.m_lc_vfs_readwrite.len = nbytes;
	int r = (_taskcall(VFS_PROC_NR, VFS_WRITE, &m));

	printf("write: %d\n", r);
	memset(&m, 0, sizeof(m));

	m.m_lc_vfs_readwrite.fd = fd;
	r = (_taskcall(VFS_PROC_NR, VFS_CLOSE, &m));

	printf("close: %d\n", r);
//	FILE *queue_log;
//	queue_log = fopen(, "w+");
//	fprintf(queue_log, "Hello Word\n");
//	fclose(queue_log );
//
	return r;
}

/*===========================================================================*
 *				do_stop_sniffing				     *
 *===========================================================================*/
int do_stop_sniffing(message *m_ptr)
{
	int i = m_ptr->hss_id;
	if(i >= HSS_MAX_SNIFFERS)
		return -1;
	sniffing_process[i].active = 0;
	return OK;
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
/* Initialize the data store server. */
	int i, r;
	struct rprocpub rprocpub[NR_BOOT_PROCS];

	/* Reset data store: data and subscriptions. */
	for(i = 0; i < HSS_MAX_SNIFFERS; i++) {
		sniffing_process[i].active = 0;
	}

	return(OK);
}