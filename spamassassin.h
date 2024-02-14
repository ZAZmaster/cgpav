#ifndef __SPAMASSASSIN_H
#define __SPAMASSASSIN_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


extern struct settings *sett;

/* this routine actually calls spamcgpavd */
int spam_scan_file(char *filename, float *score, float *threshold);

/* this routines connects to the specified socket */
int spam_connect(char *);

/* this routine closes connection to the socket */
void spam_disconnect(int);

/* this routine prints message */
void spam_message(char *message);


#endif
