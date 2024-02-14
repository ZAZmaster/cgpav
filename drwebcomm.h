#ifndef __DRWEBCOMM_H
#define __DRWEBCOMM_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "cfg.h"
#include "commoncomm.h"
#include "email.h"
#include "util.h"


extern struct settings *sett;


/* check each part of the mail message */
/* returns 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename);
			

#endif
