#ifndef __PGCOMM_H
#define __PGCOMM_H

#include <stdio.h>
#include <string.h>
#include <libpq-fe.h>

#include "cfg.h"

extern struct settings *sett;


/* get a user having settings in the database */
int get_db_user(MESSAGE *mess);


#endif
