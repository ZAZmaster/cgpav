#ifndef __KAVCOMM_H
#define __KAVCOMM_H

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
#include <ctype.h>

#include "cfg.h"
#include "commoncomm.h"
#include "email.h"
#include "util.h"


extern struct settings *sett;

/* get virus names from the AVP response */
int get_virus_names(MESSAGE *mess);

/* main scanning procedure */
int is_infected(MESSAGE *mess, char *original_filename, char *filename);


#endif
