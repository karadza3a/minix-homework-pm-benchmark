#ifndef _DS_PROTO_H
#define _DS_PROTO_H

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);

/* sniffer.c */
int do_start_sniffing(message *m_ptr);
int do_stop_sniffing(message *m_ptr);
int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
