# Makefile for HTTP Sniffer Server (HSS)
PROG=	hss
SRCS=	main.c sniffer.c

DPADD+=	${LIBSYS}
LDADD+=	-lsys -D_POSIX_SOURCE

.include <minix.service.mk>
