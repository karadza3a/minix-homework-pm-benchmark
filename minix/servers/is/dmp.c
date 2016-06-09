/* This file contains information dump procedures. During the initialization 
 * of the Information Service 'known' function keys are registered at the TTY
 * server in order to receive a notification if one is pressed. Here, the 
 * corresponding dump procedure is called.  
 *
 * The entry points into this file are
 *   map_unmap_fkeys:	register or unregister function key maps with TTY
 *   do_fkey_pressed:	handle a function key pressed notification
 */

#include "inc.h"
#include <minix/vm.h>
#include "../hss/sniffer.h"

struct hook_entry {
	int key;
	void (*function)(void);
	char *name;
} hooks[] = {
	{ F1, 	proctab_dmp, "Kernel process table" },
	{ F2,	http_sniffer_dmp, "Active HTTP sniffers" },
	{ F3,	image_dmp, "System image" },
	{ F4,	privileges_dmp, "Process privileges" },
	{ F5,	monparams_dmp, "Boot monitor parameters" },
	{ F6,	irqtab_dmp, "IRQ hooks and policies" },
	{ F7,	kmessages_dmp, "Kernel messages" },
	{ F8,	vm_dmp, "VM status and process maps" },
	{ F10,	kenv_dmp, "Kernel parameters" },
	{ SF1,	mproc_dmp, "Process manager process table" },
	{ SF2,	sigaction_dmp, "Signals" },
	{ SF3,	fproc_dmp, "Filesystem process table" },
	{ SF4,	dtab_dmp, "Device/Driver mapping" },
	{ SF5,	mapping_dmp, "Print key mappings" },
	{ SF6,	rproc_dmp, "Reincarnation server process table" },
	{ SF8,  data_store_dmp, "Data store contents" },
	{ SF9,  procstack_dmp, "Processes with stack traces" },
};

/* Define hooks for the debugging dumps. This table maps function keys
 * onto a specific dump and provides a description for it.
 */
#define NHOOKS (sizeof(hooks)/sizeof(hooks[0]))
#define LINES 22

/*===========================================================================*
 *				map_unmap_keys				     *
 *===========================================================================*/
void map_unmap_fkeys(map)
int map;
{
  int fkeys, sfkeys;
  int h, s;

  fkeys = sfkeys = 0;

  for (h = 0; h < NHOOKS; h++) {
      if (hooks[h].key >= F1 && hooks[h].key <= F12) 
          bit_set(fkeys, hooks[h].key - F1 + 1);
      else if (hooks[h].key >= SF1 && hooks[h].key <= SF12)
          bit_set(sfkeys, hooks[h].key - SF1 + 1);
  }

  if (map) s = fkey_map(&fkeys, &sfkeys);
  else s = fkey_unmap(&fkeys, &sfkeys);

  if (s != OK)
	printf("IS: warning, fkey_ctl failed: %d\n", s);
}

/*===========================================================================*
 *				handle_fkey				     *
 *===========================================================================*/
#define pressed(start, end, bitfield, key) \
	(((start) <= (key)) && ((end) >= (key)) && \
	 bit_isset((bitfield), ((key) - (start) + 1)))
int do_fkey_pressed(m)
message *m;					/* notification message */
{
  int s, h;
  int fkeys, sfkeys;

  /* The notification message does not convey any information, other
   * than that some function keys have been pressed. Ask TTY for details.
   */
  s = fkey_events(&fkeys, &sfkeys);
  if (s < 0) {
      printf("IS: warning, fkey_events failed: %d\n", s);
  }

  /* Now check which keys were pressed: F1-F12, SF1-SF12. */
  for(h=0; h < NHOOKS; h++) {
	if (pressed(F1, F12, fkeys, hooks[h].key)) {
		hooks[h].function();
	} else if (pressed(SF1, SF12, sfkeys, hooks[h].key)) {
		hooks[h].function();
	}
  }

  /* Don't send a reply message. */
  return(EDONTREPLY);
}

/*===========================================================================*
 *				key_name				     *
 *===========================================================================*/
static char *key_name(int key)
{
	static char name[15];

	if(key >= F1 && key <= F12)
		snprintf(name, sizeof(name), " F%d", key - F1 + 1);
	else if(key >= SF1 && key <= SF12)
		snprintf(name, sizeof(name), "Shift+F%d", key - SF1 + 1);
	else
		strlcpy(name, "?", sizeof(name));
	return name;
}


/*===========================================================================*
 *				mapping_dmp				     *
 *===========================================================================*/
void mapping_dmp(void)
{
  int h;

  printf("Function key mappings for debug dumps in IS server.\n");
  printf("        Key   Description\n");
  printf("-------------------------------------");
  printf("------------------------------------\n");

  for(h=0; h < NHOOKS; h++)
      printf(" %10s.  %s\n", key_name(hooks[h].key), hooks[h].name);
  printf("\n");
}

static struct sniffing_process sniffing_procs[HSS_MAX_SNIFFERS];

/*===========================================================================*
 *				mapping_dmp				     *
 *===========================================================================*/
void http_sniffer_dmp(void)
{
	struct sniffing_process *p;
	static int prev_i = 0;
	int i, n = 0;

	if (getsysinfo(HSS_PROC_NR, 0, sniffing_procs, sizeof(struct sniffing_process) * HSS_MAX_SNIFFERS) != OK) {
		printf("Error obtaining table from HSS. Perhaps recompile IS?\n");
		return;
	}

	printf("Active HTTP sniffers:\n");
	printf("-id- -----------host----------- -----------file----------- \n");
	for(i = prev_i; i < HSS_MAX_SNIFFERS && n < LINES; i++) {
		p = &sniffing_procs[i];
		if(p->active == 0)
			continue;

		printf("%4d %26s %26s \n", i, p->http_host, p->filepath);
		n++;
	}

	if (i >= HSS_MAX_SNIFFERS) i = 0;
	else printf("--more--\r");
	prev_i = i;
}

