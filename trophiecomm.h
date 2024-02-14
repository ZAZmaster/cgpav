#ifndef __TROPHIECOMM_H
#define __TROPHIECOMM_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
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


/* check each part of the mail message */
int is_infected(MESSAGE *mess, char *original_filename, char *filename); 


#endif
