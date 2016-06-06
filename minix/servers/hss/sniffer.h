#ifndef _HSS_SNIFFER_H_
#define _HSS_SNIFFER_H_

/* Type definitions for the HTTP Sniffer Server. */
#include <sys/types.h>
#include <minix/config.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <minix/endpoint.h>
#include <regex.h>

#define HSS_MAX_SNIFFERS 32 /* number of active sniffers */

struct sniffing_process {
	int active;
	char *http_host;
	char *file;
}sniffing_process[HSS_MAX_SNIFFERS];

#endif /* _HSS_SNIFFER_H_ */
