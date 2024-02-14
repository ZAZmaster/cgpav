#ifndef __SOPHOSCOMM_H
#define __SOPHOSCOMM_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "cfg.h"
#include "commoncomm.h"
#include "util.h"


extern struct settings *sett;


/* check the mail message */
/* returns 0 - not spam, 1 - spam */
int is_spam(MESSAGE *mess);


#endif
