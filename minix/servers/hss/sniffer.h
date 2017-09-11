#ifndef _HSS_SNIFFER_H_
#define _HSS_SNIFFER_H_

/* Type definitions for the HTTP Sniffer Server. */
#include <sys/types.h>
#include <minix/config.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <minix/endpoint.h>
#include <regex.h>

#define HSS_MAX_STRLEN 1024

struct remote_config {
	char username[HSS_MAX_STRLEN];
	char password[HSS_MAX_STRLEN];
	int loaded;
}remote_config;

#endif /* _HSS_SNIFFER_H_ */
