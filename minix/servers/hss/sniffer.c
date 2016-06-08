#include "inc.h"
#include "sniffer.h"

/*===========================================================================*
 *				do_start_sniffing				     *
 *===========================================================================*/
int do_start_sniffing(message *m_ptr)
{
	printf("hiyah\n#");
	return OK;
}

/*===========================================================================*
 *				do_stop_sniffing				     *
 *===========================================================================*/
int do_stop_sniffing(message *m_ptr)
{
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