#include "inc.h"
#include "sniffer.h"

/*===========================================================================*
 *				do_start_sniffing				     *
 *===========================================================================*/
int do_start_sniffing(message *m_ptr)
{
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
 *		               map_service                                   *
 *===========================================================================*/
static int map_service(const struct rprocpub *rpub)
{
///* Map a new service by registering its label. */
//	struct data_store *dsp;
//
//	/* Allocate a new data slot. */
//	if((dsp = alloc_data_slot()) == NULL) {
//		return ENOMEM;
//	}
//
//	/* Set attributes. */
//	strcpy(dsp->key, rpub->label);
//	dsp->u.u32 = (u32_t) rpub->endpoint;
//	strcpy(dsp->owner, "rs");
//	dsp->flags = DSF_IN_USE | DSF_TYPE_LABEL;
//
//	/* Update subscribers having a matching subscription. */
//	update_subscribers(dsp, 1);

	return(OK);
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

	/* Map all the services in the boot image. */
	if((r = sys_safecopyfrom(RS_PROC_NR, info->rproctab_gid, 0,
							 (vir_bytes) rprocpub, sizeof(rprocpub))) != OK) {
		panic("sys_safecopyfrom failed: %d", r);
	}
	for(i=0;i < NR_BOOT_PROCS;i++) {
		if(rprocpub[i].in_use) {
			if((r = map_service(&rprocpub[i])) != OK) {
				panic("unable to map service: %d", r);
			}
		}
	}

	return(OK);
}